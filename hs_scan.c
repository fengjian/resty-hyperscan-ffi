#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <unordered_map>
#include <chrono>
#include <unistd.h>
#include <memory>
#include <hs.h>
#include <unistd.h>


#ifndef likely
#define likely(x)      __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x)    __builtin_expect(!!(x), 0)
#endif


using std::cerr;
using std::cout;
using std::endl;
using std::ifstream;
using std::string;
using std::unordered_map;
using std::vector;



static hs_database_t *build_database(const char *const *expressions,
				     const unsigned int *flags,
				     const unsigned int *ids,
				     unsigned int elements,
				     unsigned int mode)
{
	hs_database_t *db;
	hs_compile_error_t *compile_err;
	hs_error_t err;

	err = hs_compile_multi(expressions, flags, ids,
			       elements, mode, NULL, &db, &compile_err);

	if (err != HS_SUCCESS) {
		if (compile_err->expression < 0) {
			fprintf(stderr, "ERROR: %s\n", compile_err->message);
		} else {
			fprintf(stderr, "ERROR: Pattern %s failed compile with error: %s\n", expressions[compile_err->expression], compile_err->message);
		}
		hs_free_compile_error(compile_err);
		exit(-1);
	}

	return db;
}

static unsigned parse_flags(const char *flags_str)
{
	unsigned int flags = 0;
	char c;
	while (c = *flags_str++) {
		switch (c) {
		case 'i':
			flags |= HS_FLAG_CASELESS; break;
		case 'm':
			flags |= HS_FLAG_MULTILINE; break;
		case 's':
			flags |= HS_FLAG_DOTALL; break;
		case 'H':
			flags |= HS_FLAG_SINGLEMATCH; break;
		case 'V':
			flags |= HS_FLAG_ALLOWEMPTY; break;
		case '8':
			flags |= HS_FLAG_UTF8; break;
		case 'W':
			flags |= HS_FLAG_UCP; break;
		case '\r': // stray carriage-return
			break;
		default:
			fprintf(stderr, "Unsuppoeted flag\n");
			exit(-1);
		}
	}

	return flags;
}


static void parse_file(const char *filename,
		       vector<string> &patterns,
		       vector<unsigned> &flags,
		       vector<unsigned> &ids)
{
    ifstream inFile(filename);
    if (!inFile.is_open()) {
        cerr << "ERROR: Can't open pattern file \"" << filename << "\"" << endl;
        exit(-1);
    }

    for (unsigned i = 1; !inFile.eof(); ++i) {
        string line;
        getline(inFile, line);

        // if line is empty, or a comment, we can skip it
        if (line.empty() || line[0] == '#') {
            continue;
        }

        // otherwise, it should be ID:PCRE, e.g.
        //  10001:/foobar/is

        size_t colonIdx = line.find_first_of(':');
        if (colonIdx == string::npos) {
            cerr << "ERROR: Could not parse line " << i << endl;
            exit(-1);
        }

        // we should have an unsigned int as an ID, before the colon
        unsigned id = std::stoi(line.substr(0, colonIdx).c_str());

        // rest of the expression is the PCRE
        const string expr(line.substr(colonIdx + 1));

        size_t flagsStart = expr.find_last_of('/');
        if (flagsStart == string::npos) {
            cerr << "ERROR: no trailing '/' char" << endl;
            exit(-1);
        }

        string pcre(expr.substr(1, flagsStart - 1));
        string flagsStr(expr.substr(flagsStart + 1, expr.size() - flagsStart));
        unsigned flag = parse_flags(flagsStr.c_str());

        patterns.push_back(pcre);
        flags.push_back(flag);
        ids.push_back(id);
    }
}

static void databases_from_file(const char *filename,
				hs_database_t **db_block)
{
    vector<string> patterns;
    vector<unsigned> flags;
    vector<unsigned> ids;

    parse_file(filename, patterns, flags, ids);

    vector<const char*> cstrPatterns;
    for (const auto &pattern : patterns) {
        cstrPatterns.push_back(pattern.c_str());
    }

    cout << "Compiling Hyperscan databases with " << patterns.size()
         << " patterns." << endl;

    *db_block = build_database(cstrPatterns.data(), flags.data(), ids.data(), ids.size(), HS_MODE_BLOCK);
}


#define MAX_GROUPS 512

struct match_groups {
	struct {
		unsigned long long from;
		unsigned long long to;
		unsigned int id;
	} groups[MAX_GROUPS];
	int count;
};

int on_match(unsigned int id, unsigned long long from, unsigned long long to,
	     unsigned int flags, void *ctx)
{
	struct match_groups *matches = (struct match_groups *)ctx;
	matches->groups[matches->count].id = id;
	matches->groups[matches->count].from = from;
	matches->groups[matches->count].to = to;
	matches->count++;
	return 0;
}



void serialize_database_to_file(const char *file, const char *path)
{
	hs_database_t *db_block = NULL;
	char *byte = NULL;
	size_t length = 0;
	hs_error_t err;

	databases_from_file(file, &db_block);
	err = hs_serialize_database(db_block, &byte, &length);
	if (err != HS_SUCCESS) {
		std::cerr << "ERROR: Could not serialize database. Exiting" << std::endl;
		exit(-1);
	}

	std::ofstream outfile(path, std::ofstream::binary);
	if (!outfile.is_open()) {
		std::cerr << "ERROR: Can't open: " << file << ". Exiting"<< std::endl;
		exit(-1);
	}

	outfile.write(byte, length);
	free(byte);
}



int deserialize_database_from_file(const char *filename, hs_database_t **db)
{
	std::vector<char> buf;
	size_t length = 0;

	ifstream infile(filename, std::ifstream::binary);
	if (!infile.is_open()) {
		std::cerr << "ERROR: Can't open pattern bin file \"" << filename << "\"" << std::endl;
		return -1;
	}

	infile.seekg (0, infile.end);
	length = infile.tellg();

	infile.seekg (0, infile.beg);

	buf.resize(length);
	infile.read(buf.data(), length);
	if (infile) {
		hs_error_t err = hs_deserialize_database(buf.data(), length, db);
		if (err != HS_SUCCESS) {
			std::cerr << "ERROR: Could deserialize_database bin file \"" << filename << "\"" << std::endl;
			return err;
		}
	} else {
		std::cerr << "ERROR: Can't read bin file \"" << filename << "\"" << std::endl;
		return -1;
	}

	return HS_SUCCESS;
}



static std::unordered_map<std::string, std::pair<hs_database_t*, hs_scratch_t*> > G_DBCACHE;


#ifdef __cplusplus
extern "C"
{
#endif

	int khs_init_bin_db(const char *file)
	{
		if (G_DBCACHE.find(file) == G_DBCACHE.end()) {
			hs_database_t *db_block = NULL;
			hs_scratch_t *scratch = NULL;
			int ret = deserialize_database_from_file(file, &db_block);
			if (ret != HS_SUCCESS) {
				fprintf(stderr, "ERROR: Could not deserialize database from file: %s. Exiting.\n", file);
				return ret;
			}

			hs_error_t err = hs_alloc_scratch(db_block, &scratch);
			if (err != HS_SUCCESS) {
				fprintf(stderr, "ERROR: Could not allocate scratch space. Exiting.\n");
				exit(-1);
			}
			G_DBCACHE.insert({file, {db_block, scratch}});
		}

		return HS_SUCCESS;
	}

	//only test...
	void khs_init_db(const char *file)
	{
		if (G_DBCACHE.find(file) == G_DBCACHE.end()) {
			hs_database_t *db_block = NULL;
			hs_scratch_t *scratch = NULL;

			databases_from_file(file, &db_block);

			hs_error_t err = hs_alloc_scratch(db_block, &scratch);
			if (err != HS_SUCCESS) {
				fprintf(stderr, "ERROR: Could not allocate scratch space. Exiting.\n");
				exit(-1);
			}
			G_DBCACHE.insert({file, {db_block, scratch}});
		}
	}

	int khs_block_scan_parallel(const char *file, const char **inputs, unsigned long long *lengths, void **ctxs, size_t size)
	{
		auto node_iter = G_DBCACHE.find(file);
		if (likely(node_iter != G_DBCACHE.end())) {
			hs_database_t *db_block = node_iter->second.first;
			hs_scratch_t *scratch = node_iter->second.second;

#pragma omp parallel for
			for (int i = 0; i < size; ++i) {
				hs_scan((const hs_database_t*)db_block, inputs[i], lengths[i], 0,
					(hs_scratch_t *)scratch, on_match, ctxs[i]);
			}
		}
		return -1;
	}

	int khs_block_scan(const char *file, const char *input, unsigned long long length, void *ctx)
	{
		auto node_iter = G_DBCACHE.find(file);
		if (likely(node_iter != G_DBCACHE.end())) {
			hs_database_t *db_block = node_iter->second.first;
			hs_scratch_t *scratch = node_iter->second.second;
			hs_error_t err = hs_scan((const hs_database_t*)db_block, input, length, 0,
						 (hs_scratch_t *)scratch, on_match, ctx);
			return err;
		}

		return -1;
	}

	void khs_clear_cache()
	{
		for (auto& e : G_DBCACHE) {
			auto db = e.second;
			hs_database_t *db_block = db.first;
			hs_scratch_t *scratch = db.second;

			hs_free_database(db_block);
			hs_free_scratch(scratch);
		}

		G_DBCACHE.clear();
	}

	void khs_free_db(const char *file)
	{
		if (G_DBCACHE.find(file) != G_DBCACHE.end()) {
			auto db = G_DBCACHE.at(file);
			hs_database_t *db_block = db.first;
			hs_scratch_t *scratch = db.second;

			hs_free_database(db_block);
			hs_free_scratch(scratch);

			G_DBCACHE.erase(file);
		}
	}

#ifdef __cplusplus
}
#endif



#define USAGE "Usage: hs_test -s sql_db.bat -t sql_db.bin\r\n" \
	"-s sql_db.bat 'txt db filepath'\r\n"		       \
	"-t sql_db.bin 'bin db filepath'\r\n"		       \
	"Options:\r\n"					       \
	"-h 'Display this infomation'"


int main(int argc, char *const argv[])
{
	if (argc <= 1) {
		std::cerr << USAGE << std::endl;
		exit(-1);
	}

	unsigned char flag_mask = 0b00;
	unsigned char s_flag = 0x1;
	unsigned char t_flag = 0x1 << 1;

	std::string sfile;
	std::string tfile;

	int opt;
	while ((opt = getopt(argc, argv, "hs:t:")) != -1) {
		switch (opt) {
		case 'h':
			std::cout << USAGE << std::endl;
			exit(0);
			break;
		case 's':
			if (flag_mask & s_flag) {
				std::cerr << "duplication option -s" << std::endl;
				std::cerr << USAGE << std::endl;
				exit(-1);
			}
			sfile = optarg;
			flag_mask |= s_flag;
			break;
		case 't':
			if (flag_mask & t_flag) {
				std::cerr << "duplication option -t" << std::endl;
				std::cerr << USAGE << std::endl;
				exit(-1);
			}
			tfile = optarg;
			flag_mask |= t_flag;
			break;
		default:
			std::cerr << USAGE << std::endl;
			exit(-1);
		}

	}

	if (flag_mask != 0b11) {
		if (!(flag_mask & s_flag)) {
			std::cerr << "not found option -s" << std::endl;
		}

		if (!(flag_mask & t_flag)) {
			std::cerr << "not found option -t" << std::endl;
		}

		std::cerr << USAGE << std::endl;
		exit(-1);
	}

	const char *input = sfile.c_str();
	const char *file = tfile.c_str();

	serialize_database_to_file(input, file);
	exit(0);

}

/*
 * g++ -shared -fPIC -O2 -o libhscan.so hs_test.c $(pkg-config --cflags --libs libhs)
 * g++ -O2 -o hs_test hs_test.c $(pkg-config --cflags --libs libhs)
 */

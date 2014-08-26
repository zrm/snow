#ifndef DIRECTORY_H
#define DIRECTORY_H
#include<string>
#include<vector>
#include<dirent.h>

struct dir
{
	DIR * p;
	dir() : p(nullptr) {}
	dir(const char * name);
	dir(const std::string & name);
	dir(const dir&) = delete;
	dir(dir && d) : p(d.p) { d.p = nullptr; }
	dir& operator=(dir && d) { std::swap(*this, d); return *this; }
	~dir();
};

class dirseq
{
	dir d;
public:
	dirseq(const std::string & name);
	// next() returns next directory entry, this may or may not be a regular file (e.g. subdirectory)
	std::string next();
};

bool is_dir(const std::string & name);

// constructor scans "name" and fills in files and subdirs
struct directory
{
	std::string dirname;
	std::vector<std::string> files;
	std::vector<std::string> subdirs;
	directory(const std::string & name);
	directory() {}
};

#endif // DIRECTORY_H

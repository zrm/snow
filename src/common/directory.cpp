#include "directory.h"
#include "err_out.h"

dir::dir(const char * name) : p(opendir(name)) {}
dir::dir(const std::string & name) : dir(name.c_str()) {}
dir::~dir() { if(p != nullptr) closedir(p); }

dirseq::dirseq(const std::string & name) : d(name)
{
	if(d.p == nullptr) throw check_err_exception(std::string("could not open directory ") + name);
}

std::string dirseq::next()
{
	// never use readdir_r(), readdir() is thread safe because the buffer it uses is not global but rather part of the DIR structure
	// and readdir_r() is precarious because the buffer must be heap allocated with an unintuitive size
	dirent * ent = readdir(d.p);
	if(ent != nullptr) return ent->d_name;
	return "";
}

bool is_dir(const std::string & name)
{
	dir d(name);
	return d.p != nullptr;
}

directory::directory(const std::string & name) : dirname(name)
{
	dirseq seq(name);
	std::string ent;
	while((ent = seq.next()) != "") {
		if(is_dir(name + '/' + ent))
			subdirs.push_back(ent);
		else
			files.push_back(ent);
	}
}

#ifndef PBIND_H
#define PBIND_H
#include<memory>
#include<functional>

// pbind: take member fn and [sw]ptr to class + args and bind std::function that executes iff wptr is not expired
// template args are fn ptr signature + fn ptr + std::function signature to return + wptr class type + bind arg types

// (pbind_fn is a helper to extract the argument and return types from the function pointer type)
template<typename F, F FPTR, class WPTR, typename FS = F> 
struct pbind_fn;
template<typename F, F FPTR, class WPTR, typename R, typename...Args> 
struct pbind_fn<F, FPTR, WPTR, R(WPTR::*)(Args...)>
{
	static R exec_if_lock(std::weak_ptr<WPTR> & wptr, Args...args) {
		if(std::shared_ptr<WPTR> ptr = wptr.lock())
			return (ptr.get()->*FPTR)(std::forward<Args>(args)...);
		return R();
	}
};

template<class F, F FPTR, class R, class WPTR, class... Args>
std::function<R> pbind(const std::weak_ptr<WPTR> & wptr, Args&&... args)
{
	return std::bind(&pbind_fn<F, FPTR, WPTR>::exec_if_lock, wptr, std::forward<Args>(args)...);
}
template<class F, F FPTR, class R, class WPTR, class... Args>
std::function<R> pbind(const std::shared_ptr<WPTR> & sptr, Args&&... args)
{
	std::weak_ptr<WPTR> wptr(sptr);
	return pbind<F, FPTR, R, WPTR, Args...>(wptr, std::forward<Args>(args)...);
}

// PBIND(function pointer to member, shared_ptr/weak_ptr to member, args to bind)
	// std::function signature is "void()"
// PBINDF(function pointer to member, std::function signature, shared_ptr/weak_ptr to member, args to bind)
#define PBIND(F, ...) pbind<decltype(F), F, void()>(__VA_ARGS__)
#define PBINDF(F, FP, ...) pbind<decltype(F), F, FP>(__VA_ARGS__)

// TODO: it should be possible to detect what the std::function signature should be using fn ptr and std::placeholders as std::bind does instead of having to specify it

#endif // PBIND_H

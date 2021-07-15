#pragma once

#include "common.h"


namespace pwn::utils
{
	template <class T>
	class GenericHandle
	{
	public:
		GenericHandle(T h = nullptr) :_h(h) {}
		
		~GenericHandle() 
		{ 
			close(); 
		}
		
		GenericHandle(const GenericHandle&) = delete;
		
		GenericHandle& operator=(const GenericHandle&) = delete;
		
		GenericHandle(GenericHandle&& other) noexcept : _h(other._h) 
		{ 
			other._h = nullptr; 
		}

		GenericHandle& operator=(GenericHandle&& other) noexcept
		{
			if (this != &other)
			{
				close();
				_h = other._h;
				other._h = nullptr;
			}
			return*this;
		}

		operator bool() const
		{
			return _h != nullptr && _h != INVALID_HANDLE_VALUE;
		}

		T get() const
		{
			return _h;
		}

		virtual void close()
		{
			if (bool(_h))
			{
				::CloseHandle(_h);
				_h = nullptr;
			}
		}

	protected:
		T _h;
	};


	template<typename T, typename D>
	class CustomHandle
	{
	public:
		CustomHandle(T& f, D d) : _f(f), _d(d) {}
		~CustomHandle() { _d(); }
		T get() const { return _f; }
		operator bool() const {	return _f != nullptr; }
	private:
		T _f;
		D _d;
	};
}
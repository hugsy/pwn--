
## Rust-like types and errors

Use `u8`, `i8`, `u16`, `i16` ... just like in Rust.

Results from functions in `pwn++` can be cought through the `Result<T>` templated class. Successful operation can be tested as such

```cpp
Result<int> res = MyFunction();

// Success can be tested like this:
if(Success(res))
{
    ok(L"MyFunction() returned {}", Value(res));
}

// Or for failure:
if(Failed(res))
{
    warn(L"MyFunction() failed with error {}", Error(res));
}
```

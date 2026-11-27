using Count = unsigned;

unsigned widen(unsigned short n) {
    return n;
}
Count construct(Count n) {
    return Count{n};
}

Count named_cast(int n) {
    // expected-warning@+1 {{static_cast is prohibited}}
    return static_cast<Count>(n);
}

Count c_cast(int n) {
    // expected-warning@+1 {{C-style casts are prohibited}}
    return (Count)n;
}

void discard(int n) {
    // expected-warning@+1 {{C-style casts are prohibited}}
    (void)n;
}

template <typename T>
T dependent(int n) {
    // expected-warning@+1 {{static_cast is prohibited}}
    return static_cast<T>(n);
}

#define CAST_COUNT(n) ((Count)(n))  // expected-warning {{C-style casts are prohibited}}
Count macro_user(int n) {
    return CAST_COUNT(n);
}

#define CAST_NAME static_##cast
Count pasted_macro_user(int n) {
    // expected-warning@+1 {{static_cast is prohibited}}
    return CAST_NAME<Count>(n);
}

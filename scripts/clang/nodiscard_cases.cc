void side_effect();
[[nodiscard]] int result();

// expected-warning@+1 {{non-void functions require [[nodiscard]]}}
void* address();

struct Object {
    Object();
    ~Object();
    [[nodiscard]] bool ready() const;
    // expected-warning@+1 {{non-void functions require [[nodiscard]]}}
    int value() const;
};

template <typename T>
void update(T*);

template <typename T>
// expected-warning@+1 {{non-void functions require [[nodiscard]]}}
T* ref(T* ptr) {
    return ptr;
}

template <typename T>
// expected-warning@+1 {{non-void functions require [[nodiscard]]}}
T identity(T value) {
    return value;
}

[[nodiscard]] int use() { return identity(7); }

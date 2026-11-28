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

struct [[nodiscard]] Status {};
[[nodiscard]] Status make_status();

void discard_results(const Object& object, bool condition) {
    // expected-warning@+1 {{void cast discards a [[nodiscard]] result}}
    (void)result();
    // expected-warning@+1 {{void cast discards a [[nodiscard]] result}}
    static_cast<void>(object.ready());
    // expected-warning@+1 {{void cast discards a [[nodiscard]] result}}
    (void)(condition ? result() : 0);
    // expected-warning@+1 {{void cast discards a [[nodiscard]] result}}
    (void)(side_effect(), result());
    // expected-warning@+1 {{void cast discards a [[nodiscard]] result}}
    (void)make_status();
    // expected-warning@+1 {{void cast discards a [[nodiscard]] result}}
    (void)Status{};
    (void)side_effect();
    (void)condition;
}

using Length = unsigned;
enum class Phase { Ready };
using MutableLength = Length&;

// expected-warning@+1 {{use a pointer for a mutable scalar parameter}}
void consume(MutableLength length);
// expected-warning@+1 {{use a pointer for a mutable scalar parameter}}
void advance(Phase& phase);
// expected-warning@+1 {{use a pointer for a mutable scalar parameter}}
void next(char*& cursor);

void consume(Length* length);
void read(const Length& length);
void copy(Length length);
void reset(Object& object);
[[nodiscard]] Phase& operator++(Phase& phase);
void move(Object&& object);

template <typename T>
// expected-warning@+1 {{use a pointer for a mutable scalar parameter}}
void update_value(T& value) {
    value = {};
}

void exercise_template(Length* length) {
    update_value(*length);
}

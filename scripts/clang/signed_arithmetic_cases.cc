int add(int a, int b) {
    return a + b;  // report +
}
int subtract(int a, int b) {
    return a - b;  // report -
}
int advance(int& a) {
    return ++a;  // report +
}
int retreat(int& a) {
    return a--;  // report -
}
void credit(long& a, int b) {
    a += b;  // report +
}
void debit(long& a, int b) {
    a -= b;  // report -
}
int negate(int a) {
    return -a;  // report unary -
}
int constant() {
    return 1 - 7;
}
long long widened(int a, int b) {
    return static_cast<long long>(a) + b;
}
bool guarded(int& a) {
    if (a == __INT_MAX__) return false;
    ++a;
    return true;
}
bool checked(long a, long b, long& out) {
    return !__builtin_sub_overflow(a, b, &out);
}
bool guarded_decrement(int& a) {
    if (a == -__INT_MAX__ - 1) return false;
    --a;
    return true;
}
bool too_late(int a, int b) {
    return a + b > 0;  // report +
}
unsigned unsigned_sum(unsigned a, unsigned b) {
    return a + b;
}
const char* pointer_offset(const char* p, int i) {
    return p + i;
}
static int unused_static(int a, int b) {
    return a - b;  // report -
}
inline int unused_inline(int a, int b) {
    return a + b;  // report +
}
void narrow_step(short& n) {
    ++n;  // report result conversion
    --n;  // report result conversion
}
short narrow_sum(short a, short b) {
    return a + b;  // report result conversion
}
short plain_conversion(int n) {
    return n;
}
int below_end(int i, int end) {
    if (i < end) return i + 1;
    return i;
}
int above_begin(int i, int begin) {
    if (begin >= i) return i;
    return i - 1;
}
int inclusive_end(int i, int end) {
    if (i <= end) return i + 1;  // report +
    return i;
}
int different_value(int i, int j, int end) {
    if (i < end) return j + 1;  // report +
    return j;
}
int unsigned_bound(int i, unsigned end) {
    if (static_cast<unsigned>(i) < end) return i + 1;  // report +
    return i;
}
int incomplete_merge(int i, int j, int end, bool first) {
    if (first && i >= end) return i;
    return (first ? i : j) + 1;  // report +
}
int strict_loop(int i, int end, bool skip) {
    for (; i < end; ++i)
        if (skip && i + 1 < end) ++i;
    return i;
}
int inclusive_begin(int i, int begin) {
    if (i >= begin) return i - 1;  // report -
    return i;
}
int skip_without_room(int i, int end, bool skip) {
    for (; i < end; ++i)  // report +
        if (skip) ++i;
    return i;
}

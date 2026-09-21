#ifndef __APPLE__
// Single definition of placement operator new for the entire project.
// Headers only declare it; this TU provides the definition.
void* operator new(decltype(sizeof(0)), void* p) noexcept {
    return p;
}
#endif

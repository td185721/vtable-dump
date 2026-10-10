// sample.cpp — test fixture for the PE tools' test suites.
//
// A small DLL with named exports, imports from the C runtime and KERNEL32,
// and C++ classes using single, multiple and virtual inheritance, so the
// binary carries RTTI and vtables. Built by build.cmd. SAMPLE_V2 adds an
// export and a KERNEL32 import so pe-diff has something to report.

#include <cstdio>

extern "C" __declspec(dllimport) unsigned long __stdcall GetTickCount();

namespace shapes {

struct Shape {
    virtual ~Shape() = default;
    virtual double area() const = 0;
    virtual const char* name() const { return "shape"; }
};

struct Circle : Shape {
    explicit Circle(double r) : r_(r) {}
    double area() const override { return 3.14159 * r_ * r_; }
    const char* name() const override { return "circle"; }
    double r_;
};

struct Square : Shape {
    explicit Square(double s) : s_(s) {}
    double area() const override { return s_ * s_; }
    double s_;
};

}  // namespace shapes

namespace io {

struct Reader {
    virtual ~Reader() = default;
    virtual int read() = 0;
};

struct Writer {
    virtual ~Writer() = default;
    virtual void write(int v) = 0;
    virtual void flush() {}
};

// Multiple inheritance: two vtables, the second at a non-zero offset.
struct Buffer : Reader, Writer {
    int read() override { return value_; }
    void write(int v) override { value_ = v; }
    int value_ = 0;
};

}  // namespace io

// Virtual inheritance: a diamond sharing one Node base.
struct Node {
    virtual ~Node() = default;
    virtual int id() const { return 1; }
};
struct Left : virtual Node {
    int id() const override { return 2; }
};
struct Right : virtual Node {
    virtual int weight() const { return 3; }
};
struct Diamond : Left, Right {
    int id() const override { return 4; }
    int weight() const override { return 5; }
};

// Objects are created behind exported factories so the optimizer cannot
// discard the classes, their vtables or their RTTI.
extern "C" __declspec(dllexport) void* sample_make(int kind) {
    switch (kind) {
        case 0: return static_cast<shapes::Shape*>(new shapes::Circle(1.0));
        case 1: return static_cast<shapes::Shape*>(new shapes::Square(2.0));
        case 2: return static_cast<io::Reader*>(new io::Buffer);
        default: return static_cast<Node*>(new Diamond);
    }
}

extern "C" __declspec(dllexport) double sample_area(void* shape) {
    const auto* s = static_cast<shapes::Shape*>(shape);
    std::printf("%s\n", s->name());
    return s->area();
}

extern "C" __declspec(dllexport) int sample_node_id(void* node) {
    return static_cast<Node*>(node)->id();
}

#ifdef SAMPLE_V2
extern "C" __declspec(dllexport) unsigned long sample_ticks() {
    return GetTickCount();
}
#endif

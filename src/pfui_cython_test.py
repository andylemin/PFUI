import pfui_cython
import time


def run_python_test(x):
    y = 1
    for i in range(1, x + 1):
        y *= i
    return y


# Call the print_result method
print("Print result text:")
pfui_cython.print_result(237.0)

n = 1000

start = time.time()
run_python_test(n)
end = time.time()

purePython_time = end - start
print("Pure Python time = {}".format(purePython_time))

start = time.time()
pfui_cython.test(n)
end = time.time()

Cython_time = end - start
print("Cython time = {}".format(Cython_time))
if Cython_time:
    print("Speedup = {}".format(purePython_time / Cython_time))
else:
    print("No div by zero")

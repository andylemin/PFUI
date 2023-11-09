from libc.math cimport pow

"""
def  -  regular python function, calls from Python only.
cdef -  Cython only functions, this can't be accessed from python-only code, must be called within Cython
cpdef - C and Python, this can be accessed from both C and Python
"""

cpdef int test(int x):
  cdef int y = 1
  cdef int i
  for i in range (1, x+1):
    y *= i
  return y

cdef double square_and_add (double x):
    """Compute x^2 + x as double.
    This is a cdef function that can be called from within
    a Cython program, but not from Python.
    """
    return pow(x, 2.0) + x

cpdef print_result (double x):
    """This is a cpdef function that can be called from Python."""
    print("({} ^ 2) + {} = {}".format(x, x, square_and_add(x)))

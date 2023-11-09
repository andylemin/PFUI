# Build Cython code
from distutils.core import Extension, setup
from Cython.Build import cythonize

# define an extension that will be cythonized and compiled
ext = Extension(name="pfui_cython", sources=["src/pfui_cython.pyx"])
setup(ext_modules=cythonize(ext))

# setup(ext_modules=cythonize("pfui_cython.pyx"))

# python3 setup.py clean --all
# python setup.py build_ext --inplace
# python3 setup.py install

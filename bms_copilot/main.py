import os

# OpenBLAS / PyTorch 线程控制 
# 必须在任何 PyTorch / numpy / sentence-transformers 导入之前设置，
# 否则 OpenBLAS 会按 CPU 核数创建线程级内存池，在多模型场景下极易
# 耗尽内存（"Memory allocation still failed after 10 retries"）。
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")
os.environ.setdefault("NUMEXPR_NUM_THREADS", "1")

from src.app.lifecycle import run

if __name__ == "__main__":
    run()

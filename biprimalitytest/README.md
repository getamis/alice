# Three-biprimality-test-comparison
Implement Boneh-Franklin test, Lucas biprimality test, variant Miller-Rabin test

## Overview

The Jupyter Notebook `ThreeBiprimalityTests.ipynb` implements the three biprimality tests discussed in the paper:
1.  The Boneh-Franklin (BF) test
2.  A variant of the Miller-Rabin (vMR) test
3.  Our proposed Lucas-based test

The code is used to generate the empirical results and visualizations presented in Section 5 of the paper, specifically for comparing the soundness errors of these tests. Meanwhile, it can verify foumulas of the soundness error of Boneh-Franklin, Lucas, and variant Millier-Rabin test.

## Requirements

This code is written in SageMath (tested on version 9.x) which uses a Python 3 environment. The following Python library is required for plotting:

- `matplotlib`

You can install it via pip:
```bash
pip install matplotlib
```

## How to Run and Reproduce Results

1.  Clone this repository.
2.  Open the `ThreeBiprimalityTests.ipynb` file in a Jupyter environment with a SageMath kernel.
3.  You can execute the cells sequentially to reproduce the experiments. The notebook is self-contained and includes sections for:
    - Defining the test functions.
    - Generating non-RSA moduli candidates.
    - Running the comparative experiments.

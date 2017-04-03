#!/usr/bin/env python
# -*- coding: utf-8 -*-
import matplotlib as mpl
import numpy as np
import matplotlib.pyplot as plt

data = np.genfromtxt('timingdata.csv', delimiter=',', names=['x', 'y'])
plt.plot(data['x'], data['y'], color='r', label='the data')
plt.show()
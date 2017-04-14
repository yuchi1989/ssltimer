#!/usr/bin/env python
# -*- coding: utf-8 -*-
import matplotlib as mpl
import numpy as np
import matplotlib.pyplot as plt
import csv
import scipy.stats as stat
from sklearn import linear_model
from sklearn.model_selection import cross_val_score
from sklearn import svm


def reject_outliers(data, m=2):
    return data[abs(data - np.mean(data)) < m * np.std(data)]

def left_of_mean(data):
	return data[data < np.mean(data)]

def first_quantile(data):
	return data[data < np.mean(data)]
with open('sampledata.csv', 'rb') as csvfile:
	data = []
	label = []
	samplereader = csv.reader(csvfile, delimiter=',', quotechar='|')
	for row in samplereader:
		rawdata = np.array(map(float, row[:100]))
		#awdata = reject_outliers(rawdata) #0.85
		rawdata = left_of_mean(rawdata) #0.92
		#rawdata = first_quantile(rawdata)
		kvalue = stat.kurtosis(rawdata)
		svalue = stat.skew(rawdata)
		dvalue = np.var(rawdata)/np.mean(rawdata)
		vvalue = np.var(rawdata)
		rawlabel = int(row[100])
		print ([svalue,kvalue])
		data.append(np.array([svalue,kvalue]))
		#print (data)
		label.append(rawlabel)
#clf = linear_model.SGDClassifier()
clf = svm.LinearSVC()
X = np.array(data)
Y = np.array(label)
print (X.shape)
print (Y.shape)
score = cross_val_score(clf, X, Y, cv=10)
print (score)
print (np.mean(score))

clf = svm.LinearSVC().fit(X, Y)
x_min, x_max = X[:, 0].min() - 1, X[:, 0].max() + 1
y_min, y_max = X[:, 1].min() - 1, X[:, 1].max() + 1
#x_min, x_max = X[:, 0].min() - 1, X[:, 0].max() - 3
#y_min, y_max = X[:, 1].min() - 1, X[:, 1].max() - 20
h = .005  # step size in the mesh
xx, yy = np.meshgrid(np.arange(x_min, x_max, h),
                     np.arange(y_min, y_max, h))

Z = clf.predict(np.c_[xx.ravel(), yy.ravel()])

# Put the result into a color plot
Z = Z.reshape(xx.shape)
plt.contourf(xx, yy, Z, cmap=plt.cm.coolwarm, alpha=0.8)

# Plot also the training points
plt.scatter(X[:, 0], X[:, 1], c=Y, cmap=plt.cm.coolwarm)
plt.xlabel('skewness')
plt.ylabel('kurtosis')
plt.xlim(xx.min(), xx.max())
plt.ylim(yy.min(), yy.max())
#plt.xticks(())
#plt.yticks(())
#plt.title(titles[i])

plt.show()
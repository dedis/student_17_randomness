import numpy as np
import matplotlib.pyplot as plt

"""(8, 16, 32, 64, 128)"""
N = len(hosts)
randshare_val = ()
#men_means = (20, 35, 30, 35, 27)

ind = np.arange(N)  # the x locations for the groups
width = 0.3        # the width of the bars

fig, ax = plt.subplots()
#randshare
rects1 = ax.bar(ind, randshare_val, width, color='b')

#women_means = (25, 32, 34, 20, 25)
randshare_pvss_val = ()

#ransharepvss (faire temps + verif)
rects2 = ax.bar(ind + width, randshare_pvss_val, width, color='g')

# add some text for labels, title and axes ticks
ax.set_ylabel('Wall clock time in second')
ax.set_title('Total wall clock time of a RandShare protocol run')
ax.set_xticks(ind + width / 2)
ax.set_xticklabels(('8', '16', '32', '64', '128'))

ax.legend((rects1[0], rects2[0]), ('RandShare', 'RandShare with PVSS'))


def autolabel(rects):
    """
    Attach a text label above each bar displaying its height
    """
    for rect in rects:
        height = rect.get_height()
        ax.text(rect.get_x() + rect.get_width()/2., 1.05*height,
                '%d' % int(height),
                ha='center', va='bottom')

#autolabel(rects1)
#autolabel(rects2)

plt.show()
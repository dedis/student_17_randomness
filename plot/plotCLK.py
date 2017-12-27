import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

"""(8, 16, 32, 64, 128)"""
N = 5


ind = np.arange(N)  # the x locations for the groups
width = 0.3        # the width of the bars
fig, ax = plt.subplots()
ax.set_yscale('log')

randshare_val = (1.851608, 2.669098, 26.431824, 476.390824, 0)
#men_means = (20, 35, 30, 35, 27)
#randshare
rects1 = ax.bar(ind, randshare_val, width, color='y')

#women_means = (25, 32, 34, 20, 25)
randshare_pvss_val = (2.593622, 4.971902, 16.419024, 95.415956, 570.450249)

#ransharepvss
rects2 = ax.bar(ind + width, randshare_pvss_val, width, color='red')

# add some text for labels, title and axes ticks
ax.set_ylabel('Wall clock time in second')

ax.set_xlabel('Number of nodes')
#ax.set_title('Total wall clock time of a RandShare protocol run')
ax.set_xticks(ind + width / 2)
ax.set_xticklabels(('8', '16', '32', '64', '128'))

red_patch = mpatches.Patch(color='red', label='RandShare with PVSS')
yellow_patch = mpatches.Patch(color='y', label='RandShare')
plt.legend(handles=[red_patch, yellow_patch])
#ax.legend((rects2), ('RandShare with PVSS'))


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
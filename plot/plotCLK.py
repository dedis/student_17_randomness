import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

"""(8, 16, 32, 64, 128)"""
N = 5


ind = np.arange(N)  # the x locations for the groups
width = 0.3        # the width of the bars
fig, ax = plt.subplots()
ax.set_yscale('log')

randshare_val = (2.310495, 3.923671, 8.043795, 33.1127, 119.00754)
#men_means = (20, 35, 30, 35, 27)
#randshare
rects1 = ax.bar(ind, randshare_val, width, color='c')

#women_means = (25, 32, 34, 20, 25)
#gen = (1.593877, 3.73225, 13.090557, 68.552564, 408.415956)
#verif = (0.038001, 0.144006, 0.411729, 1.674715, 6.373575)
randshare_pvss_val = (1.973887, 3.876256, 13.502286, 70.227279, 414.789531)

#ransharepvss
rects2 = ax.bar(ind + width, randshare_pvss_val, width, color='#DC143C')

# add some text for labels, title and axes ticks
ax.set_ylabel('Wall clock time in second')

ax.set_xlabel('Number of nodes')
#ax.set_title('Total wall clock time of a RandShare protocol run')
ax.set_xticks(ind + width / 2)
ax.set_xticklabels(('8', '16', '32', '64', '128'))

yellow_patch = mpatches.Patch(color='c', label='RandShare')
red_patch = mpatches.Patch(color='#DC143C', label='RandShare with PVSS')

plt.legend(handles=[yellow_patch, red_patch])
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
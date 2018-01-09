import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

"""(8, 16, 32, 64, 128)"""
N = 5

ind = np.arange(N)  # the x locations for the groups
width = 0.3        # the width of the bars
fig, ax = plt.subplots()
plt.yscale('log')

#CPU = user + system

#randshare
randshare_val = (0.24, 0.956, 10.244, 129.168, 1057.917)
p1 = plt.bar(ind, randshare_val, width, color='#9ACD32')

#ransharepvss
randshare_pvss_val = (0.34, 2.372, 24.624, 408.768, 2970.450249)
p2 = ax.bar(ind + width, randshare_pvss_val, width, color='#6495ED')

# add some text for labels, title and axes ticks
ax.set_ylabel('CPU usage in second')
ax.set_xlabel('Number of nodes')
#ax.set_title('Overall CPU usage of a RandShare protocol run')
ax.set_xticks(ind + width / 2)
ax.set_xticklabels(('8', '16', '32', '64', '128'))

yellow_patch = mpatches.Patch(color='#9ACD32', label='RandShare Randomness Generation Cost')
red_patch = mpatches.Patch(color='#6495ED', label='RandSharePVSS Randomness Generation Cost')
plt.legend(handles=[yellow_patch, red_patch])
#ax.legend((rects2), ('RandShare with PVSS'))

plt.show()
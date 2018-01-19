import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

"""(8, 16, 32, 64, 128)"""
N = 5

ind = np.arange(N)  # the x locations for the groups
width = 0.3        # the width of the bars
fig, ax = plt.subplots()
ax.set_yscale('log')

#value for 128 nodes isn't from same simulation than others

#randshare
randshare_val = (2.310495, 3.923671, 8.043795, 33.1127, 119.00754)
p1 = plt.bar(ind, randshare_val, width, color='#9ACD32')

#ransharepvss
randshare_pvss_gen_val = (1.001013, 2.369149, 9.803703, 65.270505, 414.789531)
randshare_pvss_ver_val = (0.179685, 0.784379, 4.383261, 27.47746, 193.04222)

p2 = plt.bar(ind + width, randshare_pvss_gen_val, width, color='#6495ED')
p3 = plt.bar(ind + width, randshare_pvss_ver_val, width, color='#000080', bottom=randshare_pvss_gen_val)

# add some text for labels, title and axes ticks
ax.set_ylabel('Wall clock time in second')

ax.set_xlabel('Number of nodes')
#ax.set_title('Total wall clock time of a RandShare protocol run')
ax.set_xticks(ind + width / 2)
ax.set_xticklabels(('8', '16', '32', '64', '128'))

yellow_patch = mpatches.Patch(color='#9ACD32', label='RandShare Randomness Generation')
red_patch = mpatches.Patch(color='#6495ED', label='RandSharePVSS Randomness Generation')
pink_pach = mpatches.Patch(color='#000080', label='RandSharePVSS Transcript Verification')

plt.legend(handles=[yellow_patch, red_patch, pink_pach])

x = int(5/3)
print(x)
plt.show()
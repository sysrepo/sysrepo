# Database plugins performance

## Idea
Database plugins have been developed to try to improve storage and retrieval of low amounts of data in a high-volume
data environment. Sysrepo uses a diff data structure to inform its subscribers about the changes in the data
tree, diffs however can also be sent to datastore plugins to help them store these changes. The default plugin
`JSON DS file` does not use diff and it instead parses the whole data tree into a JSON format and stores it in the file. Databases on
the other hand can be used to store only the changes from the diff and in specific use-cases speed up the whole process.

## Usage
In order to rerun performance tests, please feel free to use the Dockerfile below as suggested.

```
docker build --file scripts/db_plg_perf.Dockerfile --tag perf .
docker run --rm perf
```

## Performance

**| Options**

- Data set size      : 1000
- Each test executed : 10 times

**| Performance tests**

- **JSON DS file**

| test name                   |         time | comparison |
| --------------------------- | ------------ | ---------- |
| get tree                    |   0.001854 s | 1.000 x    |
| get item                    |   0.001778 s | 1.000 x    |
| get tree hash               |   0.001265 s | 1.000 x    |
| get tree hash cached        |   0.000011 s | 1.000 x    |
| get user ordered tree       |   0.000771 s | 1.000 x    |
| get oper tree               |   0.003297 s | 1.000 x    |
| create batch                |   0.004387 s | 1.000 x    |
| create user ordered items   |   0.007394 s | 1.000 x    |
| create all items            |   0.009278 s | 1.000 x    |
| create all items oper       |   0.009828 s | 1.000 x    |
| many oper change_subs       |   0.268622 s | 1.000 x    |
| remove all items            |   0.000290 s | 1.000 x    |
| remove all items cached     |   0.000220 s | 1.000 x    |
| remove whole subtree        |   0.000279 s | 1.000 x    |
| remove whole subtree cached |   0.000227 s | 1.000 x    |
| create an item              |   0.002188 s | 1.000 x    |
| create an item cached       |   0.001278 s | 1.000 x    |
| create an item oper         |   0.003886 s | 1.000 x    |
| modify an item              |   0.001398 s | 1.000 x    |
| modify an item cached       |   0.000505 s | 1.000 x    |
| remove an item              |   0.001403 s | 1.000 x    |
| remove an item cached       |   0.000508 s | 1.000 x    |

- **MONGO DS**

| test name                   |         time | comparison                |
| --------------------------- | ------------ | ------------------------- |
| get tree                    |   0.003391 s | $\color{#FF474C}1.829$ x  |
| get item                    |   0.004908 s | $\color{#FF474C}2.760$ x  |
| get tree hash               |   0.000210 s | $\color{#08872B}6.023$ x  |
| get tree hash cached        |   0.000091 s | $\color{#FF474C}8.272$ x  |
| get user ordered tree       |   0.002773 s | $\color{#FF474C}3.596$ x  |
| get oper tree               |   0.009505 s | $\color{#FF474C}2.882$ x  |
| create batch                |   0.015844 s | $\color{#FF474C}3.611$ x  |
| create user ordered items   |   0.116348 s | $\color{#FF474C}15.735$ x |
| create all items            |   0.019848 s | $\color{#FF474C}2.139$ x  |
| create all items oper       |   0.017425 s | $\color{#FF474C}1.772$ x  |
| many oper change_subs       |   0.656261 s | $\color{#FF474C}2.443$ x  |
| remove all items            |   0.005498 s | $\color{#FF474C}18.958$ x |
| remove all items cached     |   0.005236 s | $\color{#FF474C}23.799$ x |
| remove whole subtree        |   0.002150 s | $\color{#FF474C}7.706$ x  |
| remove whole subtree cached |   0.001359 s | $\color{#FF474C}5.986$ x  |
| create an item              |   0.004550 s | $\color{#FF474C}2.079$ x  |
| create an item cached       |   0.000725 s | $\color{#08872B}1.762$ x  |
| create an item oper         |   0.003609 s | $\color{#08872B}1.076$ x  |
| modify an item              |   0.004212 s | $\color{#FF474C}3.012$ x  |
| modify an item cached       |   0.000737 s | $\color{#FF474C}1.459$ x  |
| remove an item              |   0.003979 s | $\color{#FF474C}2.836$ x  |
| remove an item cached       |   0.000465 s | $\color{#08872B}1.092$ x  |

- **REDIS DS**

| test name                   |         time | comparison                |
| --------------------------- | ------------ | ------------------------- |
| get tree                    |   0.008860 s | $\color{#FF474C}4.778$ x  |
| get item                    |   0.011593 s | $\color{#FF474C}6.520$ x  |
| get tree hash               |   0.000079 s | $\color{#08872B}16.012$ x |
| get tree hash cached        |   0.000055 s | $\color{#FF474C}5.000$ x  |
| get user ordered tree       |   0.010339 s | $\color{#FF474C}13.409$ x |
| get oper tree               |   0.005808 s | $\color{#FF474C}1.761$ x  |
| create batch                |   0.018640 s | $\color{#FF474C}4.248$ x  |
| create user ordered items   |   0.055091 s | $\color{#FF474C}7.450$ x  |
| create all items            |   0.023312 s | $\color{#FF474C}2.512$ x  |
| create all items oper       |   0.023822 s | $\color{#FF474C}2.423$ x  |
| many oper change_subs       |   0.534279 s | $\color{#FF474C}1.988$ x  |
| remove all items            |   0.001734 s | $\color{#FF474C}5.979$ x  |
| remove all items cached     |   0.000676 s | $\color{#FF474C}3.072$ x  |
| remove whole subtree        |   0.001838 s | $\color{#FF474C}6.587$ x  |
| remove whole subtree cached |   0.000744 s | $\color{#FF474C}3.277$ x  |
| create an item              |   0.009084 s | $\color{#FF474C}4.151$ x  |
| create an item cached       |   0.000773 s | $\color{#08872B}1.653$ x  |
| create an item oper         |   0.003516 s | $\color{#08872B}1.105$ x  |
| modify an item              |   0.009051 s | $\color{#FF474C}6.474$ x  |
| modify an item cached       |   0.000476 s | $\color{#08872B}1.060$ x  |
| remove an item              |   0.008450 s | $\color{#FF474C}6.022$ x  |
| remove an item cached       |   0.000456 s | $\color{#08872B}1.114$ x  |

*All comparisons refer to how many times faster (green) or slower (red) the current plugin is compared to the first plugin.*


**| Options**

- Data set size      : 10000
- Each test executed : 10 times

**| Performance tests**

- **JSON DS file**

| test name                   |         time | comparison |
| --------------------------- | ------------ | ---------- |
| get tree                    |   0.019634 s | 1.000 x    |
| get item                    |   0.017939 s | 1.000 x    |
| get tree hash               |   0.014083 s | 1.000 x    |
| get tree hash cached        |   0.000028 s | 1.000 x    |
| get user ordered tree       |   0.007701 s | 1.000 x    |
| get oper tree               |   0.031657 s | 1.000 x    |
| create batch                |   0.047354 s | 1.000 x    |
| create user ordered items   |   0.090858 s | 1.000 x    |
| create all items            |   0.106988 s | 1.000 x    |
| create all items oper       |   0.111167 s | 1.000 x    |
| many oper change_subs       |   3.713649 s | 1.000 x    |
| remove all items            |   0.003449 s | 1.000 x    |
| remove all items cached     |   0.002566 s | 1.000 x    |
| remove whole subtree        |   0.002902 s | 1.000 x    |
| remove whole subtree cached |   0.002584 s | 1.000 x    |
| create an item              |   0.023081 s | 1.000 x    |
| create an item cached       |   0.014541 s | 1.000 x    |
| create an item oper         |   0.041899 s | 1.000 x    |
| modify an item              |   0.015329 s | 1.000 x    |
| modify an item cached       |   0.006262 s | 1.000 x    |
| remove an item              |   0.015146 s | 1.000 x    |
| remove an item cached       |   0.005578 s | 1.000 x    |

- **MONGO DS**

| test name                   |         time | comparison                |
| --------------------------- | ------------ | ------------------------- |
| get tree                    |   0.032961 s | $\color{#FF474C}1.678$ x  |
| get item                    |   0.032789 s | $\color{#FF474C}1.827$ x  |
| get tree hash               |   0.000243 s | $\color{#08872B}57.954$ x |
| get tree hash cached        |   0.000227 s | $\color{#FF474C}8.107$ x  |
| get user ordered tree       |   0.026990 s | $\color{#FF474C}3.504$ x  |
| get oper tree               |   0.034777 s | $\color{#FF474C}1.098$ x  |
| create batch                |   0.151078 s | $\color{#FF474C}3.190$ x  |
| create user ordered items   |   1.323064 s | $\color{#FF474C}14.561$ x |
| create all items            |   0.218437 s | $\color{#FF474C}2.041$ x  |
| create all items oper       |   0.165269 s | $\color{#FF474C}1.486$ x  |
| many oper change_subs       |   7.151995 s | $\color{#FF474C}1.925$ x  |
| remove all items            |   0.039869 s | $\color{#FF474C}11.559$ x |
| remove all items cached     |   0.039474 s | $\color{#FF474C}15.383$ x |
| remove whole subtree        |   0.015050 s | $\color{#FF474C}5.186$ x  |
| remove whole subtree cached |   0.013198 s | $\color{#FF474C}5.107$ x  |
| create an item              |   0.029860 s | $\color{#FF474C}1.293$ x  |
| create an item cached       |   0.007017 s | $\color{#08872B}2.072$ x  |
| create an item oper         |   0.034413 s | $\color{#08872B}1.217$ x  |
| modify an item              |   0.028166 s | $\color{#FF474C}1.837$ x  |
| modify an item cached       |   0.004840 s | $\color{#08872B}1.293$ x  |
| remove an item              |   0.026894 s | $\color{#FF474C}1.775$ x  |
| remove an item cached       |   0.004642 s | $\color{#08872B}1.201$ x  |

- **REDIS DS**

| test name                   |         time | comparison                 |
| --------------------------- | ------------ | -------------------------- |
| get tree                    |   0.095244 s | $\color{#FF474C}4.850$ x   |
| get item                    |   0.093283 s | $\color{#FF474C}5.200$ x   |
| get tree hash               |   0.000123 s | $\color{#08872B}114.495$ x |
| get tree hash cached        |   0.000153 s | $\color{#FF474C}5.464$ x   |
| get user ordered tree       |   0.148259 s | $\color{#FF474C}19.251$ x  |
| get oper tree               |   0.040969 s | $\color{#FF474C}1.294$ x   |
| create batch                |   0.220800 s | $\color{#FF474C}4.662$ x   |
| create user ordered items   |   0.627265 s | $\color{#FF474C}6.903$ x   |
| create all items            |   0.264463 s | $\color{#FF474C}2.471$ x   |
| create all items oper       |   0.265828 s | $\color{#FF474C}2.391$ x   |
| many oper change_subs       |   5.875323 s | $\color{#FF474C}1.582$ x   |
| remove all items            |   0.021471 s | $\color{#FF474C}6.225$ x   |
| remove all items cached     |   0.007099 s | $\color{#FF474C}2.766$ x   |
| remove whole subtree        |   0.022487 s | $\color{#FF474C}7.748$ x   |
| remove whole subtree cached |   0.008592 s | $\color{#FF474C}3.325$ x   |
| create an item              |   0.112921 s | $\color{#FF474C}4.892$ x   |
| create an item cached       |   0.008093 s | $\color{#08872B}1.796$ x   |
| create an item oper         |   0.041982 s | $\color{#FF474C}1.001$ x   |
| modify an item              |   0.131935 s | $\color{#FF474C}8.606$ x   |
| modify an item cached       |   0.006567 s | $\color{#FF474C}1.048$ x   |
| remove an item              |   0.113544 s | $\color{#FF474C}7.496$ x   |
| remove an item cached       |   0.006064 s | $\color{#FF474C}1.087$ x   |

*All comparisons refer to how many times faster (green) or slower (red) the current plugin is compared to the first plugin.*


**| Options**

- Data set size      : 100000
- Each test executed : 10 times

**| Performance tests**

- **JSON DS file**

| test name                   |         time | comparison |
| --------------------------- | ------------ | ---------- |
| get tree                    |   0.257987 s | 1.000 x    |
| get item                    |   0.214855 s | 1.000 x    |
| get tree hash               |   0.182746 s | 1.000 x    |
| get tree hash cached        |   0.000405 s | 1.000 x    |
| get user ordered tree       |   0.092115 s | 1.000 x    |
| get oper tree               |   0.413835 s | 1.000 x    |
| create batch                |   0.658496 s | 1.000 x    |
| create user ordered items   |   0.964103 s | 1.000 x    |
| create all items            |   1.214159 s | 1.000 x    |
| create all items oper       |   1.233159 s | 1.000 x    |
| many oper change_subs       |  42.937387 s | 1.000 x    |
| remove all items            |   0.036810 s | 1.000 x    |
| remove all items cached     |   0.043710 s | 1.000 x    |
| remove whole subtree        |   0.036970 s | 1.000 x    |
| remove whole subtree cached |   0.044760 s | 1.000 x    |
| create an item              |   0.262785 s | 1.000 x    |
| create an item cached       |   0.234830 s | 1.000 x    |
| create an item oper         |   0.778777 s | 1.000 x    |
| modify an item              |   0.162250 s | 1.000 x    |
| modify an item cached       |   0.107049 s | 1.000 x    |
| remove an item              |   0.161752 s | 1.000 x    |
| remove an item cached       |   0.105254 s | 1.000 x    |

- **MONGO DS**

| test name                   |         time | comparison                 |
| --------------------------- | ------------ | -------------------------- |
| get tree                    |   0.419329 s | $\color{#FF474C}1.625$ x   |
| get item                    |   0.415434 s | $\color{#FF474C}1.933$ x   |
| get tree hash               |   0.000278 s | $\color{#08872B}657.359$ x |
| get tree hash cached        |   0.003688 s | $\color{#FF474C}9.106$ x   |
| get user ordered tree       |   0.345308 s | $\color{#FF474C}3.748$ x   |
| get oper tree               |   0.432859 s | $\color{#FF474C}1.045$ x   |
| create batch                |   1.749139 s | $\color{#FF474C}2.656$ x   |
| create user ordered items   |  14.456433 s | $\color{#FF474C}14.994$ x  |
| create all items            |   2.360571 s | $\color{#FF474C}1.944$ x   |
| create all items oper       |   1.890673 s | $\color{#FF474C}1.533$ x   |
| many oper change_subs       |  80.463488 s | $\color{#FF474C}1.873$ x   |
| remove all items            |   0.443124 s | $\color{#FF474C}12.038$ x  |
| remove all items cached     |   0.482664 s | $\color{#FF474C}11.042$ x  |
| remove whole subtree        |   0.194736 s | $\color{#FF474C}5.267$ x   |
| remove whole subtree cached |   0.167887 s | $\color{#FF474C}3.750$ x   |
| create an item              |   0.381125 s | $\color{#FF474C}1.450$ x   |
| create an item cached       |   0.171303 s | $\color{#08872B}1.370$ x   |
| create an item oper         |   0.716619 s | $\color{#08872B}1.086$ x   |
| modify an item              |   0.343846 s | $\color{#FF474C}2.119$ x   |
| modify an item cached       |   0.100483 s | $\color{#08872B}1.065$ x   |
| remove an item              |   0.364858 s | $\color{#FF474C}2.255$ x   |
| remove an item cached       |   0.109074 s | $\color{#FF474C}1.036$ x   |

- **REDIS DS**

| test name                   |         time | comparison                  |
| --------------------------- | ------------ | --------------------------- |
| get tree                    |   1.260671 s | $\color{#FF474C}4.886$ x    |
| get item                    |   1.354169 s | $\color{#FF474C}6.302$ x    |
| get tree hash               |   0.000126 s | $\color{#08872B}1450.365$ x |
| get tree hash cached        |   0.002517 s | $\color{#FF474C}6.214$ x    |
| get user ordered tree       |   1.757068 s | $\color{#FF474C}19.074$ x   |
| get oper tree               |   0.448883 s | $\color{#FF474C}1.084$ x    |
| create batch                |   2.471534 s | $\color{#FF474C}3.753$ x    |
| create user ordered items   |   5.911053 s | $\color{#FF474C}6.131$ x    |
| create all items            |   3.006915 s | $\color{#FF474C}2.476$ x    |
| create all items oper       |   3.160048 s | $\color{#FF474C}2.562$ x    |
| many oper change_subs       |  68.550078 s | $\color{#FF474C}1.596$ x    |
| remove all items            |   0.226741 s | $\color{#FF474C}6.159$ x    |
| remove all items cached     |   0.083266 s | $\color{#FF474C}1.904$ x    |
| remove whole subtree        |   0.222872 s | $\color{#FF474C}6.028$ x    |
| remove whole subtree cached |   0.093635 s | $\color{#FF474C}2.091$ x    |
| create an item              |   1.344594 s | $\color{#FF474C}5.116$ x    |
| create an item cached       |   0.166586 s | $\color{#08872B}1.409$ x    |
| create an item oper         |   0.694264 s | $\color{#08872B}1.121$ x    |
| modify an item              |   1.245561 s | $\color{#FF474C}7.676$ x    |
| modify an item cached       |   0.108219 s | $\color{#FF474C}1.010$ x    |
| remove an item              |   1.291421 s | $\color{#FF474C}7.983$ x    |
| remove an item cached       |   0.100165 s | $\color{#08872B}1.050$ x    |

*All comparisons refer to how many times faster (green) or slower (red) the current plugin is compared to the first plugin.*


### Loading
- `get tree` retrieves the whole data tree. The XPath used for retrieval is not a Path, so databases cannot use quick prefix match to get the necessary data and have to load all the data. Databases will always be slower since loading a file is faster than loading all of the module's data from the database.
- `get item` retrieves one item. Since the XPath used for retrieval is not a Path (much like in the case of `get tree`), databases load all the data. Databases will always be slower here.
- `get tree hash` retrieves one item. Since the XPath used for retrieval is a Path, databases load only one item (and parents of this item if any), so the number of items retrieved by the databases is at most the depth of the tree where this item lies. Databases will always be faster from certain amount of items stored (at 1000 they will always be faster).
- `get tree hash cached` retrieves one item. No module's data are loaded, everything is cached. Databases will always be slower here, since checking file permissions is much faster than checking the data containing permissions from the database.
- `get user ordered items` retrieves the whole data tree. Databases will always be slower since loading a file is faster and the userordered lists and leaflists have to be sorted at the end because databases do not retrieve the data in the correct order.
- `get oper tree` retrieves the whole data tree from Operational datastore. No data are loaded, everything is cached. No permissions are checked, speed should be approximately the same.

*Note: MongoDB is faster at loading many data at once than Redis, but Redis has faster retrieval of low amounts of data.*

### Storing (big amounts of data)
- `create batch` creates a lot of items. Databases should always be slower here. Loading is performed before storing to create a diff (loading is slower).
- `create user ordered items` creates a lot of userordered items. Databases should always be much slower here. The changes from the diff have to be applied one by one (without the advantage of bulking/pipelining). Additionaly there are multiple operations per item (not just a simple store).
- `create all items` is the same as `create batch`, but the sysrepo data preparation phase takes longer (no sr_edit_batch()).
- `create all items oper` creates a lot of items in Operational datastore. Since databases also use diff for Operational datastore, the times are about the same as with `create all items` (the Operational datastore also needs to store metadata for the items, so it should be a little bit slower in this case).
- `many oper change_subs` creates and deletes a lot of items. Databases should always be slower.
- `remove all items` deletes a lot of items. Databases should always be much slower. Loading is performed before storing. Deleting one item in the database is slower than deleting one item in memory (for `JSON DS file` plugin after loading it into the memory).
- `remove all items cached` deletes a lot of items. Databases should always be slower. All data are in cache (no data loading, which is good), but deleting is still slow.
- `remove whole subtree` and `remove whole subtree cached` are the same as `remove all items` and `remove all items cached`, but MongoDB has an optimization for deleting a whole subtree (in a form of regex delete), which is faster than a regular delete of lots of items. However databases are still much slower.

*Note: MongoDB is faster at creating lots of data than Redis, but slower at deleting them. Also Redis has a much better per item insertion/deletion performance as is apparent from the `create user ordered items`*

### Storing (one item)
- `create an item` creates one item. Load is performed to create the diff, so databases are always slower.
- `create an item cached` creates one item. Load is not performed. Databases should be faster from certain amount of items stored (at 1000 they will always be faster).
- `create an item oper` creates one item in Operational datastore. Databases should be faster from certain amount of items stored, but this depends.
- `modify an item` and `remove an item` modifies and deletes one item. Databases are always slower because of loading.
- `modify an item cached` and `remove an item cached` modifies and deletes one item. Databases should have a similar performance to `JSON DS file` plugin. Modifying or deleting one item is much easier process than creating one for `JSON DS file` plugin.

### Load is faster with more data, but store is not
Loading of one item is much better for more data, because the complexity of other sysrepo processes during load is constant. Storing of one item on the other hand is not. The complexity of data validation during store is linear and so constant times during database store can only speed up the whole process so much.

$x$ is time needed for `JSON DS file` store.
<br/>
$c$ is time needed for database store.
<br/>
$y$ is time needed for validation.
<br/>
$\frac{x + y}{c + y}$ is how many times the database plugin is faster than the default `JSON DS file` plugin.
<br/>
for many items $\frac{x + y}{c + y} \approx \frac{x + y}{y} = \frac{x}{y} + \frac{y}{y} = \frac{x}{y} + 1$ ... as we can see, the final ratio is only influenced by the times of data validation and `JSON DS file` store. If we want to further speed up the process, we need to make the validation process faster.

## Final words
Database plugins should only be used when lots of small changes are expected to be made (especially creating one item periodically) and they should only be used on Running datastore using a cached connection, otherwise they will always be slower than the default `JSON DS file` plugin. If unsure, avoid them.


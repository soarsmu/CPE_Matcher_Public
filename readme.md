# CPE Matcher
## Workflow and Architecture

### Dataset
The CPE matcher is built using the training data that are provided in the dataset directory. This dataset is splitted between training data and test data with 0.75:0.25 proportion.

### Matcher Creation

 - From the training data, the **CPE libraries** of each CVE (Column "CPE_Library" of CVE_CPE_cleaned.csv) is used as the **feature**, while the **actual library names** are used as the **labels** (Column "labels" of CVE_Labels_cleaned.csv).
 - Then, we create a hashmap (dictionary) between the **feature** and the **labels**
 - Given a **feature** (list of CPE libraries) from the **test data**, we check whether the **feature** exist as **a key in the hashmap**.
 - If the **key exist**, we output the **labels** from the hashmap
- If the **key does not exist**, we use sentence similarity to find the key that is the **most similar** to the input feature.

### Illustration / Example
As an example of the above matcher creation, consider the following training and test data:
```
Training data:
CPE Library = ['debian debian_linux', 'mozilla firefox_esr', 'oracle solaris', 'mozilla firefox', 'mozilla thunderbird']
Actual Labels = ['thunderbird', 'firefox']

CPE Library = ['mozilla network_security_services']
Actual Labels = ['nss-util', 'nss', 'nspr']

CPE Library = ['mozilla network_security_services']
Actual Labels = ['nss-util', 'nss']

CPE Library = ['canonical ubuntu_linux', 'linux linux_kernel']
Actual Labels = ['kernel-rt']
```

Created Hashmap/Dictionary:
```
Key : Labels
['mozilla network_security_services'] : ['nss-util' = 2, 'nss' = 2, 'nspr' = 1],
['debian debian_linux', 'mozilla firefox_esr', 'oracle solaris', 'mozilla firefox', 'mozilla thunderbird'] : ['thunderbird' = 1, 'firefox' = 1],
['canonical ubuntu_linux', 'linux linux_kernel'] : ['kernel-rt' = 1]
```

Given the following test input feature:
```
['mozilla network_security_services']
```
The following libraries are predicted :
```
k = 1
['nss-util']

k = 2
['nss-util', 'nss']

k = 3
['nss-util', 'nss', 'nspr']
```

## Result

```
| k | precision@k | recall@k | F1@k |
|---|-------------|----------|------|
| 1 | 0.88        | 0.18     | 0.30 |
| 2 | 0.73        | 0.24     | 0.36 |
| 3 | 0.68        | 0.27     | 0.38 |
```
The above result is obtained without using the sentence similarity approach. Therefore, if a feature does not have an exact match in the hashmap, no label will be predicted.

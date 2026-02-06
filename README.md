# Project Overview

This repository contains code for alert representation learning and evaluation based on GMAE, along with data processing scripts and LLM agent prompts.

---

## Repository Structure

```
.
├── data/
├── model/
├── prompts/
├── utils/
├── train.py
├── eval_cic2017_thu.py
├── process_data_by_metapath_networkX_in_use.py
├── README.md
└── .git/
```

---

## Directory Descriptions

### `prompts/`
This directory stores **LLM agent prompt templates**.

---

### `data/`
This directory stores alert data generated using **Snort3**, and the alerts are labeled according to the dataset provided at:  
https://www.unb.ca/cic/datasets/ids-2017.html

---

### `model/`
This directory contains the **GMAE model code**.

---

### `utils/`
This directory contains **utility code for GMAE**.

---

## Python Files

### `process_data_by_metapath_networkX_in_use.py`
This script **organizes CSV data into NetworkX graphs**.

---

### `train.py`
This script is used to **train the model**, and training continues until **no new minimum loss is observed for 15 consecutive epochs**.

---

### `eval_cic2017_thu.py`
This script is used to **perform evaluation and generate related JSON files**.
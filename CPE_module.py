from sklearn.model_selection import train_test_split
from skmultilearn.model_selection import iterative_train_test_split
from sentence_transformers import SentenceTransformer, util

cleaned_CPE_data_path = "dataset/CVE_CPE_cleaned.csv"
DATASET_PATH = "dataset/final_dataset_merged_cleaned.csv"

import re
import pandas as pd
import requests
import numpy as np


# helper function to remove symbols other than underscore from the sentence
def remove_symbols(sentence):
    return re.sub('[^a-zA-Z_0-9 -/]+', '', sentence)

def remove_comma_quote(sentence: str):
    sentence = sentence.replace("'", "")
    sentence = sentence.replace('"', "")
    sentence = sentence.replace(',', "")
    return sentence


# Read the cleaned dataset csv file and split the dataset into train and test data
def data_preparation(nrows=None):
    df_CPE = pd.read_csv(cleaned_CPE_data_path, usecols=["cve_id", "CPE_Library"], nrows=nrows)

    # lower the library name
    df_CPE["CPE_Library"] = df_CPE["CPE_Library"].str.lower()
    # remove symbols from the data

    df_CPE["CPE_Library"] = df_CPE["CPE_Library"].apply(remove_symbols)
    df_CPE["CPE_Library"] = df_CPE["CPE_Library"].apply(remove_comma_quote)
    # Read column names from file
    cols = list(pd.read_csv(DATASET_PATH, nrows=1))
    df_labels = pd.read_csv(DATASET_PATH, usecols =[i for i in cols if i not in ["cve_id", "cleaned", "matchers", "merged"]], nrows=nrows)

    data = df_CPE.to_numpy()
    labels = df_labels.to_numpy()
    # Split dataset using skmultilearn (for multi-label classification)

    train, label_train, test, label_test = iterative_train_test_split(data, labels, test_size=0.25)
    # print("Train")
    # print(train)
    # print(label_train)
    # print("Test")
    # print(test)
    # print(label_test)
    return train, label_train, test, label_test

# from the cleaned CVE_CPE csv, create a basic matcher
def create_cpe_matcher():
    # train, label_train, test, label_test = data_preparation(nrows=None)
    # train
    train, label_train, test, label_test = data_preparation(nrows=None)

    # make the matcher from the train data first
    matcher_dict = {}
    df_labels = pd.read_csv("dataset/CVE_Labels_cleaned.csv", nrows=None)
    for data in train:
        # check if data[1] (CPE library names) is in matcher dict
        # if not, initiate dictionary
        if data[1] not in matcher_dict:
            matcher_dict[data[1]] = {}
        # get the label
        label_dict = matcher_dict[data[1]]
        row = df_labels[df_labels["cve_id"] == data[0]]
        label_split = row['labels'].values[0].split(",")
        for label in label_split:
            label = remove_symbols(label)
            label = label.strip()
            if label in label_dict:
                label_dict[label] += 1
            else:
                label_dict[label] = 1
    model = SentenceTransformer('paraphrase-MiniLM-L6-v2')
    # for key, value in matcher_dict.items():
    #     print(key)
    #     print(value)

    # match the test data here
    # amount of correct prediction
    n_correct_predict = 0
    n_prediction = 0
    n_actual_labels = 0

    ordered_dict_key = list(matcher_dict.keys())
    ordered_key_embedding = model.encode(ordered_dict_key)
    # print(ordered_dict_key)
    # print(ordered_key_embedding)

    for i in range(len(test)):
        data = test[i]
        # cpe_library is the CPE libraries list of the test data
        cpe_library = data[1]
        if cpe_library in matcher_dict:
            # Use this to get all the possible labels (lower precision, higher recall)
            # predicted_labels = list(matcher_dict[cpe_library].keys())


            # Use this to get the top-n most probable labels
            # change n to any integer
            # n = 5
            # predicted_labels = sorted(matcher_dict[cpe_library], key=matcher_dict[cpe_library].get, reverse=True)[:n]

            # Use this to get only the labels that appear more than the average
            predicted_labels = []
            library_name, library_occurence = list(matcher_dict[cpe_library].keys()), list(matcher_dict[cpe_library].values())
            # calculate the average
            sum = 0
            for occur in library_occurence:
                sum += occur
            average = sum / len(library_occurence)
            for j in range(len(library_name)):
                if library_occurence[j] >= average:
                    predicted_labels.append(library_name[j])
        else:
            # use several approach to get the most similar cpe entry
            # 1. Try to use sentence transformers to create the embedding and use cosine similarity
            # create the embedding from the cpe_library
            cpe_library_embedding = model.encode(cpe_library)
            # calculate the cosine similarity?
            cos_sim = util.cos_sim(ordered_key_embedding, cpe_library_embedding).tolist()

            # get max value and its index
            max_value = max(cos_sim)
            max_index = cos_sim.index(max_value)
            # get the predicted labels

            # Use this to get all possible labels (lower precision)
            # predicted_labels = list(matcher_dict[ordered_dict_key[max_index]].keys())

            # Use this to get the labels that are above average
            predicted_labels = []
            library_name, library_occurence = list(matcher_dict[ordered_dict_key[max_index]].keys()), list(matcher_dict[ordered_dict_key[max_index]].values())
            # calculate the average
            sum = 0
            for occur in library_occurence:
                sum += occur
            average = sum / len(library_occurence)
            for j in range(len(library_name)):
                if library_occurence[j] >= average:
                    predicted_labels.append(library_name[j])
            # predicted_labels = []

        row = df_labels[df_labels["cve_id"] == data[0]]
        # clean the actual labels first (remove symbol, trim, etc)
        actual_labels = remove_symbols(row['labels'].values[0]).split(",")
        # print("Actual labels: " + actual_labels.__str__())

        # print(actual_labels)
        # At this point, the actual labels contain the actual labels of the CVE
        # Meanwhile, the predicted labels contain the predicted labels based on the CPE matching

        # Count the metrics necessary to calculate precision and recall
        # Add the number of prediction to n_prediction
        n_prediction += len(predicted_labels)

        # Add the number of actual labels
        n_actual_labels += len(actual_labels)

        # Count the number of correct prediction
        for correct_label in actual_labels:
            if correct_label.strip() in predicted_labels:
                n_correct_predict += 1
    print("Number correct prediction: " + n_correct_predict.__str__())
    print("Number prediction done: " + n_prediction.__str__())
    print("Number of actual labels: " + n_actual_labels.__str__())
    print("Precision: " + (n_correct_predict / n_prediction).__str__())
    print("Recall: " + (n_correct_predict / n_actual_labels).__str__())


# process_raw_cpe()
create_cpe_matcher()





# crawl_cpe()
#
# r = requests.get('https://services.nvd.nist.gov/rest/json/cve/1.0/CVE-2015-7580')
# response = r.json()
# if "result" in response:
#     # SHOULD LOOP THE NODES
#     list_cpes_nodes = response['result']['CVE_Items'][0]['configurations']['nodes']
#     print(list_cpes_nodes)
#     cve_cpe = []
#     for node in list_cpes_nodes:
#         list_cpes = node['cpe_match']
#         for cpe in list_cpes:
#             cve_cpe.append(cpe['cpe23Uri'])
#         # look in the children too
#         children = node['children']
#         for child in children:
#             list_cpes = child['cpe_match']
#             for cpe in list_cpes:
#                 cve_cpe.append(cpe['cpe23Uri'])
#     print(cve_cpe)
# else:
#     print("NO RESULT FOR")
#

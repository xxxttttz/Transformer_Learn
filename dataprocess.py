import os

import numpy as np
import pandas as pd
import torch
from scapy.layers.inet import IP
from scapy.utils import rdpcap
from sklearn.model_selection import train_test_split
from itertools import combinations


def get_IOT_ip():
    path = "/raid/device-IP.xlsx"
    device_list = pd.read_excel(path)
    ip_list = []
    name_list = []
    for row in device_list.itertuples():
        ip_list.append(row[2])
        name_list.append(row[1])
    device_ip_dict = dict(zip(name_list, ip_list))

    return device_ip_dict #返回设备与IP地址的键值对列表

def get_label():
    """
    :param path: 设备文件名列表
    :return:
    """
    path = "/raid/device-IP.xlsx"
    device_list = pd.read_excel(path)
    label_list = []
    name_list = []
    for label,row in enumerate(device_list.itertuples()):
        label_list.append(label)
        name_list.append(row[1])

    device_label_dict = dict(zip(name_list,label_list))
    return device_label_dict



def process_data(path,save_path):
    dir = os.listdir(path)
    X = []
    y = []
    device_ip_dict = get_IOT_ip()
    device_label_dict = get_label()
    for name in dir:
        print(f"Processing {name}.pcap")
        pcap_path = f"{path}/{name}/{name}.pcap"
        data = []
        packets = rdpcap(pcap_path)
        for pkt in packets:
            timestamp = pkt.time
            if IP in pkt:
                if pkt[IP].src == device_ip_dict[name]:
                    data.append(timestamp)
                elif pkt[IP].dst == device_ip_dict[name]:
                    data.append(-1*timestamp)

        print(f"data len is {len(data)}")
        lab = torch.zeros(1,77)
        lab[0,device_label_dict[name]] = 1
        if len(data) < 10000:
            for i in range(10000-len(data)):data.append(0)
            X.append(data)
            y.append(lab)
        else :
            idx = len(data)//10000 + 1
            for i in range(idx*10000-len(data)):data.append(0)
            for i in range(idx):
                X.append(data[i*10000:(i+1)*10000])
                y.append(lab)

        print(f"X len is {len(X)}, y len is {len(y)}")


    X = np.array(X).astype(np.float64)
    y = np.array(y)
    y = y.reshape(-1,77)
    print(f"X shape is {X.shape}, y shape is {y.shape}")
    save_file = f"{save_path}/1tag.npz"
    np.savez(save_file, X=X, y=y)
    print(f"{save_file}生成完成！")
    return X,y



# process_data("/raid/raw_traffic","/raid/traffic_feature_npz")
#
# data = np.load("/raid/traffic_feature_npz/1tag.npz", allow_pickle=True)

def get_data(name,path):
    device_ip_dict = get_IOT_ip()
    device_label_dict = get_label()
    data = []
    packets = rdpcap(f"{path}/{name}/{name}.pcap")
    for pkt in packets:
        timestamp = pkt.time
        if IP in pkt:
            if pkt[IP].src == device_ip_dict[name]:
                data.append(timestamp)
            elif pkt[IP].dst == device_ip_dict[name]:
                data.append(-1 * timestamp)
    lab = device_label_dict[name]
    return data,lab


def mul_tab(path,save_path):
    dir = os.listdir(path)
    X = []
    y = []
    for name in combinations(dir, 2):
        lab = torch.zeros(1,77)
        # if name1!=name2:
        X1,y1 = get_data(name[0],path)
        X2,y2 = get_data(name[1],path)
        print(f"X1 len is {len(X1)}, X2 len is {len(X2)}")
        data = X1 + X2
        lab[0,y1]=1
        lab[0,y2]=1
        data = sorted(data,key=abs)
        print(f"data len is {len(data)}")
        if len(data) < 10000:
            for i in range(10000 - len(data)): data.append(0)
            X.append(data)
            y.append(lab)
        else:
            idx = len(data) // 10000 + 1
            for i in range(idx * 10000 - len(data)): data.append(0)
            for i in range(idx):
                X.append(data[i * 10000:(i + 1) * 10000])
                y.append(lab)
        print(f"X len is {len(X)}, y len is {len(y)}")
    X = np.array(X).astype(np.float64)
    y = np.array(y)
    y = y.reshape(-1, 77)
    print(f"X shape is {X.shape}, y shape is {y.shape}")
    save_file = f"{save_path}/2tag.npz"
    np.savez(save_file, X=X, y=y)
    print(f"{save_file}生成完成！")
    return X, y





X,y = mul_tab("/raid/raw_traffic","/raid/traffic_feature_npz")







#
# data = np.load("/raid/closed_2tab.npz", allow_pickle=True)
# X = data["X"]
# y = data["y"]
#
#
# X_train, X_test, y_train, y_test = train_test_split(X, y, train_size=0.9)
# X_train, X_valid, y_train, y_valid = train_test_split(X_train, y_train, train_size=0.9)
#
# print(f"Train: X = {X_train.shape}, y = {y_train.shape}")
# print(f"Valid: X = {X_valid.shape}, y = {y_valid.shape}")
# print(f"Test: X = {X_test.shape}, y = {y_test.shape}")
#
# dataset_path = "/raid/traffic_feature_npz"
# # Save the split datasets into separate .npz files
# np.savez(os.path.join(dataset_path, "train.npz"), X = X_train, y = y_train)
# np.savez(os.path.join(dataset_path, "valid.npz"), X = X_valid, y = y_valid)
# np.savez(os.path.join(dataset_path, "test.npz"), X = X_test, y = y_test)

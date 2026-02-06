import torch
import warnings
# import faiss
from model.autoencoder import build_model
from utils.utils import set_random_seed
import numpy as np
from utils.config import build_args
warnings.filterwarnings('ignore')
from sklearn.cluster import dbscan
from scipy.sparse import csr_matrix
from sklearn.preprocessing import StandardScaler
from sklearn.manifold import TSNE
import matplotlib.pyplot as plt
from sklearn.neighbors import NearestNeighbors
import time

from sklearn.metrics import homogeneity_completeness_v_measure
from scipy.stats import entropy as scipy_entropy
from collections import Counter

import pickle as pkl
import json
def load_metadata(path):
    with open(f'{path}/metadata.json', 'r', encoding='utf-8') as f:
        metadata = json.load(f)
    return metadata
def load_entity_level_dataset(path, t,n):
    '''
        1. metadata.json 存储 节点维度、边维度、训练结合来源图数量、测试集合来源图数量 和 恶意实体 相关的元信息
        2. 从 $t$n.pkl 中反序列化得到对应的一张来源图
    '''
    with open('{}/{}{}.pkl'.format(path, t,n), 'rb') as f:
        data = pkl.load(f)
    return data


def compute_k_distance(embeddings, k):
    """
    embeddings: np.ndarray of shape (N, d)
    k: min_samples
    return: np.ndarray of shape (N,), k-distance for each point
    """
    nbrs = NearestNeighbors(
        n_neighbors=k + 1,  # +1 是因为包含自身
        metric="euclidean",
        n_jobs=-1
    )
    nbrs.fit(embeddings)

    distances, _ = nbrs.kneighbors(embeddings)

    # distances[:, 0] 是 0（自己）
    # distances[:, k] 是第 k 个邻居的距离
    k_distances = distances[:, k]

    return k_distances

def estimate_epsilon(k_distances, percentile=90):
    """
    percentile: 通常取 85~95
    """
    eps = np.percentile(k_distances, percentile)
    return eps

class MainArgs():
    def __init__(self, num_hidden, num_layers,n_dim,e_dim):  # 构造函数
        self.num_hidden = num_hidden
        self.num_layers = num_layers
        self.n_dim = n_dim
        self.e_dim = e_dim
class ClusterWrapper():
    def __init__(self, scaler={}):
        self.kdtree = {}
        self.cluster = {}
        self.cluster_mask = {}
        self.model = {}
        # 新样本使用相同的scaler
        self.scaler = scaler

    # 按类别聚类，首先训练集进行按类别聚类，然后为每一聚类都打上标签
    def cluster_all(self, X_emb, X, Y):
        # 按类别做分类
        for cate in np.unique(X).tolist():
            cate_mask = np.where(X == cate)[0]
            cate_X_emb = X_emb[cate_mask]

            if cate not in self.scaler.keys():
                scaler = StandardScaler()
                self.scaler[cate] = scaler
            else:
                scaler = self.scaler[cate]
            cate_X_emb = scaler.fit_transform(X=cate_X_emb)
            cate_X_emb, _, inverse_indices, counts  = np.unique(cate_X_emb,
                               return_inverse=True,
                               return_index=True, 
                               return_counts=True,
                               axis=0
                        )
            # print(cate_mask.shape[0], cate_X_emb.shape[0])
            # eps = get_eps(cate_X_emb)
            # print(eps)
            _,labels = dbscan(
                cate_X_emb,
                eps           = 4, # 新的使用 3.5 更好
                min_samples   = 2,
                sample_weight = counts,
                p             = 2,
            )
            this_cluster = labels[inverse_indices]
            # 各类聚类
            self.cluster[cate] = this_cluster
            # 原始下标 # 11.6 <感觉是原始nx_g的序号>
            self.cluster_mask[cate] = cate_mask
            # print(f"cluster_all: {cate} {np.unique(self.cluster[cate]).shape}")
        return scaler

    def print_cluster(self, Y, path):
        rownum_with_cluster = {}

        count_all = 0
        count_all2 = 0

        un_cluster = 0
        all_cluster = 0
        clustered = 0

        overrate = 0
        underrate = 0
        max_index = 0

        all_ok_cluster = 0
        total_homogeneity = 0

        sum_prob = 0
        sum_prob_count = 0

        all_l0_cluster = []
        all_l1_cluster = []
        all_l2_cluster = []
        all_l3_cluster = []
        all_sus_cluster = []
        all_cluster_in = []

        # 新增：收集所有非噪声样本用于 sklearn 同质性计算
        all_labels_true = []   # 真实标签
        all_labels_pred = []   # 聚类分配
        # 新增：收集多标签 cate 的非噪声样本
        multi_labels_true = []   # 多标签 cate 的真实标签
        multi_labels_pred = []   # 多标签 cate 的聚类分配
        # 新增：收集熵值计算所需数据
        all_cluster_entropies = []      # 所有聚类的 (熵, 样本数)
        multi_cluster_entropies = []    # 多标签 cate 聚类的 (熵, 样本数)
        # 新增：收集采样概率数据
        all_cluster_probs = []          # 所有聚类的 (概率, 样本数)
        multi_cluster_probs = []        # 多标签 cate 聚类的 (概率, 样本数)

        # 新增：统计-1类（噪声点）中各级别的数量
        noise_l0 = 0
        noise_l1 = 0
        noise_l2 = 0
        noise_l3 = 0
        # 统计全体告警中各级别的数量
        total_l0 = 0
        total_l1 = 0
        total_l2 = 0
        total_l3 = 0

        for cate,cluster in self.cluster.items():
            # 包含当前类别下的所有下标
            if cate not in rownum_with_cluster.keys():
                rownum_with_cluster[cate] = {}

            cate_mask = self.cluster_mask[cate]

            # 判断该 cate 是否存在多种标签
            cate_labels = Y[cate_mask]
            unique_labels_in_cate = np.unique(cate_labels)
            is_multi_label_cate = len(unique_labels_in_cate) > 1

            # 收集该 cate 下所有非噪声样本的 (真实标签, 聚类ID)
            for i, c1 in enumerate(cluster):
                if c1 != -1:  # 排除噪声点
                    all_labels_true.append(Y[cate_mask[i]])
                    all_labels_pred.append(f"{cate}_{c1}")  # 全局唯一的聚类ID
                    # 如果是多标签 cate，也收集到 multi_labels 中
                    if is_multi_label_cate:
                        multi_labels_true.append(Y[cate_mask[i]])
                        multi_labels_pred.append(f"{cate}_{c1}")

            # 拿到在 cate_mask 中的下标 (对应 cluster 的下标)
            level0 = np.where(Y[cate_mask] == 0)[0]
            level1 = np.where(Y[cate_mask] == 1)[0]
            level2 = np.where(Y[cate_mask] == 2)[0]
            level3 = np.where(Y[cate_mask] == 3)[0]

            # 累计全体告警中各级别的数量
            total_l0 += len(level0)
            total_l1 += len(level1)
            total_l2 += len(level2)
            total_l3 += len(level3)

            d = 0
            if len(level0) == 0:
                d += 1
            if len(level1) == 0:
                d += 1
            if len(level2) == 0:
                d += 1
            if len(level3) == 0:
                d += 1
            
            unique, counts = np.unique(cluster, return_counts=True)
            count_all += unique.shape[0]
            print("cate", cate,":"," l0:", len(level0),",l1:", len(level1),",l2:",len(level2),",l3:", len(level3))

            boo = False
            if cate == 119:
                boo = True
            for c1, count in zip(unique, counts):
                # 拿到在当前 cluster 中的下标
                # if boo and (c1 == 6 or c1 == 10):
                #     print("debugger")
                mask = np.where(cluster == c1)[0]

                # 获取当前类别下，某个子聚类的真实下标
                if c1.item() not in rownum_with_cluster[cate].keys():
                    rownum_with_cluster[cate][c1.item()] = cate_mask[mask].tolist()

                # 计算同质性，以 数量最多的为真实标签
                l0 = len(list(set(mask) & set(level0)))
                l1 = len(list(set(mask) & set(level1)))
                l2 = len(list(set(mask) & set(level2)))
                l3 = len(list(set(mask) & set(level3)))

                # 如果是噪声点(-1类)，统计各级别数量
                if c1 == -1:
                    noise_l0 += l0
                    noise_l1 += l1
                    noise_l2 += l2
                    noise_l3 += l3


                if c1 != -1:
                    all_cluster_in.append(len(mask))

                    # 计算该聚类的熵值
                    label_counts = [l0, l1, l2, l3]
                    total_in_cluster = sum(label_counts)
                    if total_in_cluster > 0:
                        probs = [c / total_in_cluster for c in label_counts if c > 0]
                        cluster_entropy = scipy_entropy(probs, base=2)  # 以2为底的熵
                    else:
                        cluster_entropy = 0.0
                    all_cluster_entropies.append((cluster_entropy, total_in_cluster))
                    if is_multi_label_cate:
                        multi_cluster_entropies.append((cluster_entropy, total_in_cluster))

                    # 计算该聚类的采样概率 (k=2)
                    label_counts_arr = [l0, l1, l2, l3]
                    N = total_in_cluster
                    k = 3
                    # 找到最高风险等级
                    max_level = -1
                    for level in [3, 2, 1, 0]:
                        if label_counts_arr[level] > 0:
                            max_level = level
                            break
                    if max_level >= 0:
                        h = label_counts_arr[max_level]
                        if N < k:
                            # 采样数量超过总量，必然采到最高风险
                            prob = 1.0
                        else:
                            prob = calculate_probability(N, h, k)
                        all_cluster_probs.append((prob, N))
                        if is_multi_label_cate:
                            multi_cluster_probs.append((prob, N))

                    # 统计集群
                    d0 = 0
                    if l0 != 0:
                        d0 += 1
                    if l1 != 0:
                        d0 += 1
                    if l2 != 0:
                        d0 += 1
                    if l3 != 0:
                        d0 += 1
                    
                    if d0 == 1:
                        if l0 != 0:
                            all_l0_cluster.append(l0)
                        elif l1 != 0:
                            all_l1_cluster.append(l1)
                        elif l2 != 0:
                            all_l2_cluster.append(l2)
                        elif l3 != 0:
                            all_l3_cluster.append(l3)
                    else:
                        all_sus_cluster.append(len(mask))


                if c1 != -1:
                    count_all2 += 1

                if d != 3:
                    l0 = len(list(set(mask) & set(level0)))
                    l1 = len(list(set(mask) & set(level1)))
                    l2 = len(list(set(mask) & set(level2)))
                    l3 = len(list(set(mask) & set(level3)))
                    print(f"cluster: {c1:5d}, count: {count:5d}, \
                        l0:{l0:5d}, \
                        l1:{l1:5d}, \
                        l2:{l2:5d}, \
                        l3:{l3:5d}"
                        )


                    arr = [l0,l1,l2,l3]
                    idx = max(range(4), key=lambda i: arr[i])
                    y_true = np.full(len(mask), idx)
                    y_true = np.concatenate((y_true, np.array([0,1,2,3])))
                    h, c, v = homogeneity_completeness_v_measure(y_true, \
                                                    np.concatenate((Y[cate_mask[mask]], np.array([0,1,2,3]))),\
                                                    beta=0.8)
                    # print(f"H={h:.3f}, C={c:.3f}, V={v:.3f}")
                    # 计算 存在多级别告警的分类 的 平均同质性
                    if c1 != -1:
                        total_homogeneity += h
                        all_ok_cluster += 1

                    if c1 != -1:
                        max_value = 0
                        for index, value in enumerate([l0,l1,l2,l3]):
                            if value > max_value:
                                max_value = value
                                max_index = index
                        c1
                        for index, value in enumerate([l0,l1,l2,l3]):
                            if index < max_index:
                                overrate += value
                            elif index > max_index:
                                underrate += value

                all_cluster += count
                if c1 == -1:
                    un_cluster += count
                else:
                    clustered += count

        # 新增：打印噪声点(-1类)的统计信息
        print("\n" + "=" * 80)
        print("\n*** 噪声点(-1类)告警统计 ***\n")
        noise_total = noise_l0 + noise_l1 + noise_l2 + noise_l3
        if noise_total > 0:
            print(f"噪声点总数: {noise_total}")
            print(f"  Level 0: {noise_l0:6d} ({noise_l0/noise_total*100:6.2f}%)")
            print(f"  Level 1: {noise_l1:6d} ({noise_l1/noise_total*100:6.2f}%)")
            print(f"  Level 2: {noise_l2:6d} ({noise_l2/noise_total*100:6.2f}%)")
            print(f"  Level 3: {noise_l3:6d} ({noise_l3/noise_total*100:6.2f}%)")
            print(f"\n噪声点在全体告警中的占比: {noise_total/all_cluster*100:.2f}%")
        else:
            print("无噪声点")

        print("\n全体告警各级别统计:")
        all_total = total_l0 + total_l1 + total_l2 + total_l3
        print(f"全体告警总数: {all_total}")
        print(f"  Level 0: {total_l0:6d} ({total_l0/all_total*100:6.2f}%)")
        print(f"  Level 1: {total_l1:6d} ({total_l1/all_total*100:6.2f}%)")
        print(f"  Level 2: {total_l2:6d} ({total_l2/all_total*100:6.2f}%)")
        print(f"  Level 3: {total_l3:6d} ({total_l3/all_total*100:6.2f}%)")

        print("\n噪声点各级别在全体该级别中的占比:")
        if total_l0 > 0:
            print(f"  噪声L0/全体L0: {noise_l0}/{total_l0} = {noise_l0/total_l0*100:.2f}%")
        else:
            print(f"  噪声L0/全体L0: {noise_l0}/0 = N/A")
        if total_l1 > 0:
            print(f"  噪声L1/全体L1: {noise_l1}/{total_l1} = {noise_l1/total_l1*100:.2f}%")
        else:
            print(f"  噪声L1/全体L1: {noise_l1}/0 = N/A")
        if total_l2 > 0:
            print(f"  噪声L2/全体L2: {noise_l2}/{total_l2} = {noise_l2/total_l2*100:.2f}%")
        else:
            print(f"  噪声L2/全体L2: {noise_l2}/0 = N/A")
        if total_l3 > 0:
            print(f"  噪声L3/全体L3: {noise_l3}/{total_l3} = {noise_l3/total_l3*100:.2f}%")
        else:
            print(f"  噪声L3/全体L3: {noise_l3}/0 = N/A")
        print("=" * 80)

        # 新增：计算并打印 sklearn 同质性指标
        print("\n" + "=" * 80)
        print("\n*** SKLEARN METRICS (ALL SESSIONS - 排除噪声点) ***\n")
        if len(all_labels_true) > 0:
            sklearn_h, sklearn_c, sklearn_v = homogeneity_completeness_v_measure(
                all_labels_true, all_labels_pred
            )
            print(f"Homogeneity:  {sklearn_h:.6f}")
            print(f"Completeness: {sklearn_c:.6f}")
            print(f"V-measure:    {sklearn_v:.6f}")
            print(f"样本数: {len(all_labels_true)}")
        else:
            print("无非噪声样本")

        print("\n" + "=" * 80)
        print("\n*** SKLEARN METRICS (MULTI-LABEL CATE ONLY - 排除噪声点) ***\n")
        if len(multi_labels_true) > 0:
            multi_h, multi_c, multi_v = homogeneity_completeness_v_measure(
                multi_labels_true, multi_labels_pred
            )
            print(f"Homogeneity:  {multi_h:.6f}")
            print(f"Completeness: {multi_c:.6f}")
            print(f"V-measure:    {multi_v:.6f}")
            print(f"样本数: {len(multi_labels_true)}")
        else:
            print("无多标签 cate 的非噪声样本")
        print("=" * 80)

        # 新增：计算并打印熵值统计
        print("\n" + "=" * 80)
        print("\n*** ENTROPY METRICS (ALL SESSIONS - 排除噪声点) ***\n")
        if len(all_cluster_entropies) > 0:
            total_samples_all = sum(size for _, size in all_cluster_entropies)
            avg_entropy_unweighted = sum(e for e, _ in all_cluster_entropies) / len(all_cluster_entropies)
            avg_entropy_weighted = sum(e * size for e, size in all_cluster_entropies) / total_samples_all
            pure_clusters = sum(1 for e, _ in all_cluster_entropies if e == 0)
            mixed_clusters = sum(1 for e, _ in all_cluster_entropies if e > 0)
            print(f"平均熵（非加权）: {avg_entropy_unweighted:.6f}")
            print(f"平均熵（加权）:   {avg_entropy_weighted:.6f}")
            print(f"聚类数: {len(all_cluster_entropies)}")
            print(f"纯净聚类数（熵=0）: {pure_clusters}")
            print(f"混合聚类数（熵>0）: {mixed_clusters}")
        else:
            print("无非噪声聚类")

        print("\n" + "=" * 80)
        print("\n*** ENTROPY METRICS (MULTI-LABEL CATE ONLY - 排除噪声点) ***\n")
        if len(multi_cluster_entropies) > 0:
            total_samples_multi = sum(size for _, size in multi_cluster_entropies)
            avg_entropy_unweighted_multi = sum(e for e, _ in multi_cluster_entropies) / len(multi_cluster_entropies)
            avg_entropy_weighted_multi = sum(e * size for e, size in multi_cluster_entropies) / total_samples_multi
            pure_clusters_multi = sum(1 for e, _ in multi_cluster_entropies if e == 0)
            mixed_clusters_multi = sum(1 for e, _ in multi_cluster_entropies if e > 0)
            print(f"平均熵（非加权）: {avg_entropy_unweighted_multi:.6f}")
            print(f"平均熵（加权）:   {avg_entropy_weighted_multi:.6f}")
            print(f"聚类数: {len(multi_cluster_entropies)}")
            print(f"纯净聚类数（熵=0）: {pure_clusters_multi}")
            print(f"混合聚类数（熵>0）: {mixed_clusters_multi}")
        else:
            print("无多标签 cate 的非噪声聚类")
        print("=" * 80)

        # 新增：打印采样概率统计
        print("\n" + "=" * 80)
        print("\n*** SAMPLING PROBABILITY METRICS (k=2, ALL SESSIONS - 排除噪声点) ***\n")
        if len(all_cluster_probs) > 0:
            total_samples_all = sum(size for _, size in all_cluster_probs)
            avg_prob_unweighted = sum(p for p, _ in all_cluster_probs) / len(all_cluster_probs)
            avg_prob_weighted = sum(p * size for p, size in all_cluster_probs) / total_samples_all
            print(f"平均概率（非加权）: {avg_prob_unweighted:.6f}")
            print(f"平均概率（加权）:   {avg_prob_weighted:.6f}")
            print(f"聚类数: {len(all_cluster_probs)}")
        else:
            print("无非噪声聚类")

        print("\n" + "=" * 80)
        print("\n*** SAMPLING PROBABILITY METRICS (k=2, MULTI-LABEL CATE ONLY - 排除噪声点) ***\n")
        if len(multi_cluster_probs) > 0:
            total_samples_multi = sum(size for _, size in multi_cluster_probs)
            avg_prob_unweighted_multi = sum(p for p, _ in multi_cluster_probs) / len(multi_cluster_probs)
            avg_prob_weighted_multi = sum(p * size for p, size in multi_cluster_probs) / total_samples_multi
            print(f"平均概率（非加权）: {avg_prob_unweighted_multi:.6f}")
            print(f"平均概率（加权）:   {avg_prob_weighted_multi:.6f}")
            print(f"聚类数: {len(multi_cluster_probs)}")
        else:
            print("无多标签 cate 的非噪声聚类")
        print("=" * 80)

        # 存储各聚类的原始行号
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(rownum_with_cluster, f, indent=4)

        return count_all

def get_cluster_things(data):
    mean = sum(data) / len(data)
    variance = sum((x - mean) ** 2 for x in data) / len(data)
    std_dev = variance ** 0.5
    return mean, min(data), max(data), std_dev

import math
def calculate_probability(N, n, k):
    """
    计算至少发现一个最高风险等级警报的概率。
    
    参数:
    N (int): 集群中警报的总数。
    n (int): 集群中最高风险等级警报的数量。
    k (int): 抽取的警报数量。
    
    返回:
    float: 至少发现一个最高风险等级警报的概率。
    """
    if k > N:
        return 1.0  # 采样数量超过总量，必然采到最高风险

    # 计算组合数
    total_ways = math.comb(N, k)
    no_highest_risk_ways = math.comb(N - n, k)
    
    # 计算至少发现一个最高风险等级警报的概率
    probability = 1 - (no_highest_risk_ways / total_ways)
    return probability

# main
if __name__ == '__main__':
    main_args = build_args()
    device = 0
    device = torch.device(device)
    dataset_name = '/root/OwnWork/data/CIC2017/model_test/one/' # 实验在 two -> 64维 4头 /root/OwnWork/data/CIC2017/model_test/one/
    main_args.num_hidden = 64
    main_args.num_layers = 3
    set_random_seed(0)

    metadata = load_metadata(dataset_name)
    main_args.n_dim = metadata['node_feature_dim'] + metadata['sig_dim']
    main_args.e_dim = metadata['edge_feature_dim']
    model = build_model(main_args)
    model.load_state_dict(torch.load("{}/checkpoint-{}.pt".format(dataset_name,'cic2017'), map_location=device))
    model = model.to(device)
    model.eval()
    # n_test = metadata['n_test']
    n_train = metadata['n_train']

    # print("打印模型：\n", model)

    with torch.no_grad():
        # 训练集
        x_train = []
        y_train = []
        x_train_emb = []
        idx_train = []
        for i in range(0, n_train):
            g = load_entity_level_dataset(dataset_name, 'train',i)
            g = g.to(device) # 验证 g 图的标签
            # Exclude training samples from the test set
            x_train.append(g.ndata['ntype'].cpu().numpy())
            x_train_emb.append(model.embed(g).cpu().numpy())
            y_train.append(g.ndata['label'].cpu().numpy())

            # 获取csv 行号
            idx_train.append(g.ndata['idx'].cpu().numpy())
            if idx_train[0].tolist() == sorted(idx_train[0].tolist()):
                print("sorted!!!")

            cluster_wrapper = ClusterWrapper()
            # 总是拿第一个来排序
            scaler = cluster_wrapper.cluster_all(x_train_emb[0], x_train[0], y_train[0])
            path = "./data/rownum_with_cluster.json"
            ret = cluster_wrapper.print_cluster(y_train[0], path)
            print(ret)

import dgl
import json
import torch
import pandas   as pd
import numpy    as np
import networkx as nx
import pickle   as pkl

import torch.nn.functional as F
import torch.nn as nn

from tqdm import tqdm

from datetime import datetime



# 构建图，理论上所有的告警都可以按上述ip划分集群
# 实体类型字典
node_type_dict = {}
# 边类型字典
edge_type_dict = {}
node_type_cnt = 0
edge_type_cnt = 0


def CICProcess(src_path):
    data = pd.read_csv(src_path, encoding='latin1')
    all_alert_type = data['sid'].tolist()
    all_alert_level = data['level_label'].tolist()
    all_alert_time = data['timestamp'].tolist()
    all_alert_category = data['class'].tolist()
    all_host = data['host'].tolist()
    all_host_ip = data['host'].tolist()
    all_src_ip = data['src_addr'].tolist()
    all_dst_ip = data['dst_addr'].tolist()
    all_src_port = data['src_port'].tolist()
    all_dst_port = data['dst_port'].tolist()
    all_edge_type = data['proto'].tolist()

    return (all_alert_type,all_alert_level, \
            all_alert_time,all_host, \
            all_host_ip,all_alert_category, \
            all_src_ip,all_dst_ip, \
            all_edge_type, all_src_port, all_dst_port)

# 预处理数据集
def ProcessDataset(src_path, store_path, dataset='cptc'):
    '''
        src_path: 源路径
        store_path： 目标路径
        dataset： 数据集种类
        -----
        (alert_type, connect_type)
    '''
    if dataset == 'cptc':
        all_alert_type,all_alert_level,\
        all_alert_time,all_host, \
        all_host_ip,all_alert_category, \
        all_src_ip,all_dst_ip, \
        all_edge_type,\
        all_src_port, all_dst_port = CPTCProcess(src_path)
    elif dataset == 'cic':
        all_alert_type,all_alert_level,\
        all_alert_time,all_host, \
        all_host_ip,all_alert_category, \
        all_src_ip,all_dst_ip, \
        all_edge_type,\
        all_src_port, all_dst_port = CICProcess(src_path)
    else:
        print("error dataset preprocess")
        return
    all_data = {
        "timestamp":all_alert_time,
        "machine":all_host,
        "machine_ip": all_host_ip,
        "signature":all_alert_type, # 暂时不用
        "label":all_alert_level,
        # "category": all_alert_category, # 大类别
        "category": all_alert_type, # 改变分类的类型
        "src_ip":all_src_ip,
        "dst_ip":all_dst_ip,
        "src_port":all_src_port,
        "dst_port":all_dst_port,
        "edge_type": all_edge_type
    }

    df = pd.DataFrame(all_data)
    # 存储前先完成排序
    df = df.sort_values(by='timestamp')
    df.to_csv(store_path, index=False, encoding='utf-8')
    return len(set(all_alert_type))

# 将数据组织成图
def Data2Graph(data, maps):
    global event_map_reverse
    global edge_map_reverse
    global ips_map_reverse
    nx_g = nx.DiGraph() # 有向多图
    # s_nx_g = nx.DiGraph()    # 有向简单图

    edge_types_th = F.one_hot(torch.tensor([0,1,2,3]), num_classes=4).float() # 已修改
    edge_types = {"host":edge_types_th[0], "service":edge_types_th[1], \
                  "tactics":edge_types_th[2], "freq":edge_types_th[2]}

    for etype in edge_types.keys():
        # 构建图中节点，以及处理组内关系
        for e,item in tqdm(data.groupby(etype)):
            min_time = int(item['timestamp'].iloc[0])
            # 先处理组内关系 rownum: 原始DataFrame中的索引值
            for i, (rownum,rowdata) in enumerate(item.iterrows()):
                this_time = int(rowdata["timestamp"])
                the_map = maps[etype][e][(this_time - min_time) // 3600] # numpy
                item_len = the_map.shape[0]
                if the_map[i] != rownum:
                    print("error order")

                if i + 60 >= item_len: 
                    random_indices = range(i + 1, item_len)
                else:
                    random_indices = range(i + 1, i + 60)
                random_samples = the_map[random_indices].tolist()
                nx_g.add_node(rownum, \
                    ntype=rowdata['sid'], \
                    label=rowdata['level_label'], \
                    idx=rownum
                )
                for random_sample in random_samples:
                    # 临时添加节点，用于连接边
                    nx_g.add_node(random_sample, \
                        ntype=-1007, \
                        label=-1007, \
                        idx=random_sample
                    )
                    if nx_g.has_edge(rownum, random_sample):
                        tmp_edges = nx_g[rownum][random_sample]['etype']
                        etypes = [tmp_edges, edge_types[etype]]
                        mean_etype = torch.stack(etypes).mean(dim=0)
                        nx_g.add_edge(rownum, random_sample, etype=mean_etype)
                    else:
                        nx_g.add_edge(rownum, random_sample, etype=edge_types[etype])
    # 换成简单图
    # for u,v in nx_g.edges():
    #     etypes = [nx_g[u][v][key]['etype'] for key in nx_g[u][v]]
    #     mean_etype = 
    #     s_nx_g.add_edge(u,v, etype=mean_etype)
    for node in nx_g.nodes():
        if nx_g.nodes[node].get("ntype") == -1007 or nx_g.nodes[node].get("label") == -1007:
            print(node)
    print(nx_g)
    return nx_g

def InitMaps(data, all=True):
    # 1. 同主机告警关联  考虑要不要融合二阶元路径做边 （比如权重下降）
    metapaths = [
        # 1. 同主机告警关联
        [("alert", "tri_on", "host"), ("host", "rev_tri_on", "alert")],
        # 2. 同服务告警关联
        [("alert", "tar_to", "service"), ("service", "rev_tar_to", "alert")],
        # 3. 同攻击阶段告警关联
        [("alert", "belong", "tactics"), ("tactics", "rev_belong", "alert")],
        # 4. 同频率告警关联
        [("alert", "has", "freq"), ("freq", "rev_has", "alert")]
    ]
    # 2. 将data数据按边类型分组，然后按时间戳分桶
    cates = ["host", "service", "tactics", "freq"] #
    all_data = {}
    for cate in cates:
        this_data = {}
        data_num = []
        for ca, group in data.groupby(cate):
            this_data[ca] = {}

            time_list = group["timestamp"].tolist()
            min_time = int(time_list[0])
            max_time = int(time_list[-1])
            gap_time = ((max_time - min_time) // 3600) + 1 # 1h
            np_group_time = group["timestamp"].values
            index_group = group.index
            for i in range(gap_time):
                this_data[ca][i] = {}

                mask1 = np.where(np_group_time >= min_time)[0].tolist()
                mask2 = np.where(np_group_time < min_time + (i + 2) * 3600)[0].tolist()
                mask = sorted(list(set(mask1) & set(mask2)))
                this_data[ca][i] = index_group[mask].values # np数组
                # this_data[ca][i]['ts'] = np_group_time[mask] # np数组
                # data_num += this_data[ca][i]['data'].tolist()
        # print(len(set(data_num)))
        all_data[cate] = this_data

    return all_data
    

def transform_graph(g, node_feature_dim, edge_feature_dim, signature_dim=0):
    '''
        1. 将 实体类型 和 边 进行 ont-hot 编码
        2. 没有改变原始图的形状
        3. 增加一个可学习的 Embedding
    '''
    new_g = g.clone()
    new_g.ndata["attr"] = F.one_hot(g.ndata["ntype"].view(-1), num_classes=node_feature_dim).float()
    new_g.edata["attr"] = g.edata["etype"]
    
    # # 增加节点向量的维度
    # emb = nn.Embedding(num_embeddings=signature_dim, embedding_dim=16)
    # new_g.ndata["attr"] = torch.concat((new_g.ndata["attr"], emb(g.ndata["sigs"].view(-1))), dim=1)

    return new_g

if __name__ == '__main__':
    
    # 在 6_cic 已经排序过了，不再重复排序
    data = pd.read_csv('./data/cic2017_thu_fixed.csv', encoding='latin1')
    # data = data.sort_values(by="timestamp")
    
    sid_map = { k:v for v,k in enumerate(np.unique(data["sid"]).tolist())}
    data['sid'] = data['sid'].map(sid_map)
    maps = InitMaps(data, all=False)

    all_label = data['level_label'].values
    level0 = np.where(all_label == 0)
    level1 = np.where(all_label == 1)
    level2 = np.where(all_label == 2)
    level3 = np.where(all_label == 3)
    metadata = {
        "node_feature_dim": len(np.unique(data['sid'].values)),
        "edge_feature_dim":4,
        "sig_dim":0,
        "n_train":1,
        "level0":level0[0].tolist(),
        "level1":level1[0].tolist(), # 下标，也是新行号
        "level2":level2[0].tolist(),
        "level3":level3[0].tolist(),
        # "events":events.tolist()
        "sid_map":sid_map
    }

    with open('./data/metadata.json', 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=4)
    for i in range(0,1):
        nx_g = Data2Graph(data, maps)
        dgl_g = dgl.from_networkx(nx_g, node_attrs=['ntype', 'label', 'idx'],edge_attrs=['etype'])
        dim_ntype = len(torch.unique(dgl_g.ndata['ntype']))
        dim_etype = 4
        new_g = transform_graph(dgl_g, dim_ntype, dim_etype)
        print(new_g)
        with open('./data/train{}.pkl'.format(i), 'wb') as f:
            pkl.dump(
                (new_g)
                , f
            )
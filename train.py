import os
import random
import torch
import warnings
from tqdm import tqdm
from model.autoencoder import build_model
from torch.utils.data.sampler import SubsetRandomSampler
from dgl.dataloading import GraphDataLoader
from utils.utils import set_random_seed, create_optimizer
from utils.config import build_args
warnings.filterwarnings('ignore')


def extract_dataloaders(entries, batch_size):
    random.shuffle(entries)
    train_idx = torch.arange(len(entries))
    train_sampler = SubsetRandomSampler(train_idx)
    train_loader = GraphDataLoader(entries, batch_size=batch_size, sampler=train_sampler)
    return train_loader

import json
def load_metadata(path):
    with open(f'{path}/metadata.json', 'r', encoding='utf-8') as f:
        metadata = json.load(f)
    return metadata
""""""
import pickle as pkl
import time
def load_entity_level_dataset(path, m,n):
    '''
        1. metadata.json 存储 节点维度、边维度、训练结合来源图数量、测试集合来源图数量 和 恶意实体 相关的元信息
        2. 从 $t$n.pkl 中反序列化得到对应的一张来源图
    '''
    while not os.path.exists('{}/{}{}.pkl'.format(path,m,n)):
        print("waiting ......")
        time.sleep(3)
    with open('{}/{}{}.pkl'.format(path,m,n), 'rb') as f:
        data = pkl.load(f)
    return data

def main(main_args):
    device = main_args.device if main_args.device >= 0 else "cpu"
    dataset_name = '/root/OwnWork/data/CIC2017/model_test/one/' # '/root/OwnWork/data/CIC2017/model_test/4_48/'
    main_args.num_hidden = 64
    # main_args.max_epoch = 200 # 设计早停策略
    main_args.max_epoch = 10000
    main_args.num_layers = 3
    main_args.max_cnt = 15   # 早停条件
    set_random_seed(0)

    # 加载该数据集中的一些元信息
    metadata = load_metadata(dataset_name)
    main_args.n_dim = metadata['node_feature_dim'] + metadata['sig_dim']
    main_args.e_dim = metadata['edge_feature_dim']
    model = build_model(main_args)
    print(model)
    model = model.to(device)
    model.train()
    optimizer = create_optimizer(main_args.optimizer, model, main_args.lr, main_args.weight_decay)
    epoch_iter = tqdm(range(main_args.max_epoch))
    n_train = metadata['n_train']

    # epoch_loss = 0
    best_loss = 1e9
    best_state = 0
    cnt_wait = 0
    best_eps = 0
    for epoch in epoch_iter:
        g = load_entity_level_dataset(dataset_name, "train", 0)
        g = g.to(device)
        print(g)
        model.train()
        # 使用模型对 之前得到的来源图做推理
        loss = model(g)
        loss /= n_train
        optimizer.zero_grad()
        # epoch_loss += loss.item()
        if best_loss > loss:
            best_loss = loss
            best_eps  = epoch
            best_state = model.state_dict()
            cnt_wait = 0
        else:
            cnt_wait += 1
        if cnt_wait >= main_args.max_cnt:
            print('Early stopping!')
            break
        # 梯度下降
        loss.backward()
        optimizer.step()
        # 打印进度条
        epoch_iter.set_description(f"Epoch {epoch} | train_loss: {loss:.4f} | cnt_wait: {cnt_wait}")
    print(f'The best epoch is: {best_eps}, loss is {best_loss}')
    model.load_state_dict(best_state)
    # 将模型参数保存到本地的文件中
    torch.save(model.state_dict(), "{}/checkpoint-{}.pt".format(dataset_name, 'cic2017'))

    return


if __name__ == '__main__':
    args = build_args()
    main(args)

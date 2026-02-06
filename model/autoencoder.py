from .gat import GAT
from utils.utils import create_norm
from functools import partial
from itertools import chain
from .loss_func import sce_loss
import torch
import torch.nn as nn
import dgl
import random

# 下面的代码注释仅针对trace等实体信息级别的数据集

def build_model(args):
    num_hidden = args.num_hidden          # 64
    num_layers = args.num_layers          # 3
    negative_slope = args.negative_slope  # 0.2    LeakyReLU 激活函数来处理计算注意力系数时得到的中间结果，
                                          #             而 negative_slope 参数正是用来控制 LeakyReLU 在输入为
                                          #                 负值时的斜率。
                                          #        标准的 ReLU 函数对于负数输入直接输出 0，这可能会导致梯度消失的问题。
                                          #             而 LeakyReLU 则在输入为负数时不会完全“关断”，而是乘以一个较小的系数，
                                          #                 即 negative_slope。公式为： negative_slope * 注意力系数
    mask_rate = args.mask_rate            # 0.5
    alpha_l = args.alpha_l                # 3      用于增强惩罚 (余弦相似度)
    n_dim = args.n_dim                    # 节点种类
    e_dim = args.e_dim                    # 边种类

    model = GMAEModel(
        n_dim=n_dim,
        e_dim=e_dim,
        hidden_dim=num_hidden,
        n_layers=num_layers,
        n_heads=4,   # 可以填4
        activation="prelu",
        feat_drop=0.1,
        negative_slope=negative_slope,
        residual=True,
        mask_rate=mask_rate,
        norm='BatchNorm',
        loss_fn='sce',
        alpha_l=alpha_l
    )
    return model


class GMAEModel(nn.Module):
    def __init__(self, n_dim, e_dim, hidden_dim, n_layers, n_heads, activation,
                 feat_drop, negative_slope, residual, norm, mask_rate=0.5, loss_fn="sce", alpha_l=2):
        super(GMAEModel, self).__init__()
        self._mask_rate = mask_rate
        self._output_hidden_size = hidden_dim
        self.recon_loss = nn.BCELoss(reduction='mean') #  PyTorch 中的二元交叉熵损失函数，
                                                       #    用于计算二分类问题中预测概率与真实标签之间的差异。

        def init_weights(m):
            if isinstance(m, nn.Linear):
                nn.init.xavier_uniform(m.weight)       # 使用 Xavier 均匀初始化方法（xavier_uniform_）对其权重进行初始化。
                                                       # Xavier 初始化是一种常用的方法，旨在保持前向传播和反向传播过程中信号的
                                                       # 方差一致，有助于避免梯度消失或爆炸的问题。
                nn.init.constant_(m.bias, 0)

        self.edge_recon_fc = nn.Sequential(
            nn.Linear(hidden_dim * n_layers * 2, hidden_dim), # 这层将输入特征的维度从 
                                                              #     hidden_dim * n_layers * 2 映射到 hidden_dim
            nn.LeakyReLU(negative_slope), # LeakyReLU 是一种改进的 ReLU 激活函数，
                                          #     允许小于零的输入值以一个很小的斜率通过，从而缓解 ReLU 的“死亡”问题。
            nn.Linear(hidden_dim, 1),     # 将特征维度从 hidden_dim 映射到 1，输出一个标量值，表示边存在的可能性。
            nn.Sigmoid()                  # Sigmoid 函数将输入映射到 (0, 1) 区间，输出可以被解释为概率值，表示边存在的概率。
        )
        self.edge_recon_fc.apply(init_weights) # 初始化重建全连接层相关参数

        assert hidden_dim % n_heads == 0
        enc_num_hidden = hidden_dim // n_heads
        enc_nhead = n_heads

        dec_in_dim = hidden_dim
        dec_num_hidden = hidden_dim

        # build encoder
        self.encoder = GAT(
            n_dim=n_dim,
            e_dim=e_dim,
            hidden_dim=enc_num_hidden,
            out_dim=enc_num_hidden,
            n_layers=n_layers,
            n_heads=enc_nhead,
            n_heads_out=enc_nhead,
            concat_out=True,
            activation=activation,
            feat_drop=feat_drop,
            attn_drop=0.0,
            negative_slope=negative_slope,
            residual=residual,
            norm=create_norm(norm),
            encoding=True,
        )

        # build decoder for attribute prediction
        self.decoder = GAT(
            n_dim=dec_in_dim,
            e_dim=e_dim,
            hidden_dim=dec_num_hidden,
            out_dim=n_dim,
            n_layers=1,
            n_heads=n_heads,
            n_heads_out=1,
            concat_out=True,
            activation=activation,
            feat_drop=feat_drop,
            attn_drop=0.0,
            negative_slope=negative_slope,
            residual=residual,
            norm=create_norm(norm),
            encoding=False,
        )

        # 首先定义一个可训练的掩码标记参数，用于在编码器输入中标记特定位置；
        #   ​然后定义一个不带偏置的线性层，实现从编码器到解码器的特征维度转换。

        self.enc_mask_token = nn.Parameter(torch.zeros(1, n_dim)) # one hot编码，全零编码为masked node向量
        self.encoder_to_decoder = nn.Linear(dec_in_dim * n_layers, dec_in_dim, bias=False)

        # * setup loss function
        self.criterion = self.setup_loss_fn(loss_fn, alpha_l)

    @property
    def output_hidden_dim(self):
        return self._output_hidden_size

    def setup_loss_fn(self, loss_fn, alpha_l): # 初始化损失函数
        if loss_fn == "sce":
            criterion = partial(sce_loss, alpha=alpha_l) # 不用每次都手动指定这个参数了;固定了alpha_l参数值
        else:
            raise NotImplementedError
        return criterion

    # 2025/06/12 修改，增加 valid_num 参数
    def encoding_mask_noise(self, g, mask_rate=0.3, valid_num=0):
        new_g = g.clone()
        num_nodes = g.num_nodes() if not valid_num else valid_num
        perm = torch.randperm(num_nodes, device=g.device) # 产生随机数序列 [0, num_nodes-1] 随机排列

        # random masking
        num_mask_nodes = int(mask_rate * num_nodes)       # 计算掩码数量
        mask_nodes = perm[: num_mask_nodes]               # 前 num_mask_nodes 的节点被掩盖
        keep_nodes = perm[num_mask_nodes:]                # 代表未被掩码的节点

        new_g.ndata["attr"][mask_nodes] = self.enc_mask_token # 被掩码的节点更新到新图中。

        return new_g, (mask_nodes, keep_nodes)

    # 2025/06/12 修改，增加 valid_num 参数
    def forward(self, g, valid_num=0):                                 # 前向函数，计算loss而已
        loss = self.compute_loss(g, valid_num)
        return loss

    # 2025/06/12 修改，增加 valid_num 参数
    def compute_loss(self, g, valid_num):
        # Feature Reconstruction
        pre_use_g, (mask_nodes, keep_nodes) = self.encoding_mask_noise(g, self._mask_rate, valid_num)
        pre_use_x = pre_use_g.ndata['attr'].to(pre_use_g.device)    # 新图中节点的属性
        use_g = pre_use_g                                           # 使用被掩盖后的图
        enc_rep, all_hidden = self.encoder(use_g, pre_use_x, return_hidden=True)
        enc_rep = torch.cat(all_hidden, dim=1)

        rep = self.encoder_to_decoder(enc_rep) # 编码器输出，转换为, 解码器输入

        recon = self.decoder(pre_use_g, rep)
        x_init = g.ndata['attr'][mask_nodes]
        x_rec = recon[mask_nodes] # 节点特征重建
        loss = self.criterion(x_rec, x_init)
        
        # loss = 0


        # 如果能在负采样这里做出点新意，倒是很好！！！！！！ 目前这里没有表现出必要性，可能是数据集的原因
        # Structural Reconstruction
        threshold = min(5000, g.num_nodes())

        # 负样本边对采样涉及从图中选择实际上不存在的边作为负例。
        negative_edge_pairs = dgl.sampling.global_uniform_negative_sampling(g, threshold)
        # 正样本边对采样是指从原始图中选取实际存在的边作为训练数据中的正例。​
        positive_edge_pairs = random.sample(range(g.number_of_edges()), threshold)
        positive_edge_pairs = (g.edges()[0][positive_edge_pairs], g.edges()[1][positive_edge_pairs])

        sample_src = enc_rep[torch.cat([positive_edge_pairs[0], negative_edge_pairs[0]])].to(g.device)
        sample_dst = enc_rep[torch.cat([positive_edge_pairs[1], negative_edge_pairs[1]])].to(g.device)
        # ​全连接层能够将源节点和目标节点的嵌入表示进行线性组合，学习它们之间的关系，有助于捕捉更复杂的交互信息。
        y_pred = self.edge_recon_fc(torch.cat([sample_src, sample_dst], dim=-1)).squeeze(-1)
        y = torch.cat([torch.ones(len(positive_edge_pairs[0])), torch.zeros(len(negative_edge_pairs[0]))]).to(
            g.device)
        loss += self.recon_loss(y_pred, y) # 计算结构重建的损失。
        return loss

    def embed(self, g):
        x = g.ndata['attr'].to(g.device)
        rep = self.encoder(g, x)
        # rep = g.ndata['attr']
        return rep

    @property
    def enc_params(self):
        return self.encoder.parameters()

    @property
    def dec_params(self):
        return chain(*[self.encoder_to_decoder.parameters(), self.decoder.parameters()])

import torch
import torch.nn as nn
# edge_softmax 函数用于对图中的边进行归一化，计算每个节点的入边的注意力权重。
from dgl.ops import edge_softmax
# DGL 提供的内置消息传递函数集合，简称为 fn。
#   这些函数用于定义图神经网络中的消息传递和聚合操作，例如消息的发送、接收和组合等。
import dgl.function as fn
# expand_as_pair 函数用于将输入特征扩展为源节点和目标节点的特征对。
from dgl.utils import expand_as_pair
# create_activation 用于根据指定的激活函数名称创建对应的激活函数实例。
from utils.utils import create_activation


class GAT(nn.Module):
    def __init__(self,
                 n_dim,
                 e_dim,
                 hidden_dim,
                 out_dim,
                 n_layers,
                 n_heads,
                 n_heads_out,
                 activation,
                 feat_drop,
                 attn_drop,
                 negative_slope,
                 residual,
                 norm,
                 concat_out=False,
                 encoding=False
                 ):
        super(GAT, self).__init__()
        self.out_dim = out_dim
        self.n_heads = n_heads
        self.n_layers = n_layers
        self.gats = nn.ModuleList()
        self.concat_out = concat_out

        last_activation = create_activation(activation) if encoding else None
        last_residual = (encoding and residual)
        last_norm = norm if encoding else None

        if self.n_layers == 1:
            self.gats.append(GATConv(
                n_dim, e_dim, out_dim, n_heads_out, feat_drop, attn_drop, negative_slope,
                last_residual, norm=last_norm, concat_out=self.concat_out
            ))
        else:
            self.gats.append(GATConv(
                n_dim, e_dim, hidden_dim, n_heads, feat_drop, attn_drop, negative_slope,
                residual, create_activation(activation),
                norm=norm, concat_out=self.concat_out
            ))
            for _ in range(1, self.n_layers - 1):
                self.gats.append(GATConv(
                    hidden_dim * self.n_heads, e_dim, hidden_dim, n_heads,
                    feat_drop, attn_drop, negative_slope,
                    residual, create_activation(activation),
                    norm=norm, concat_out=self.concat_out
                ))
            self.gats.append(GATConv(
                hidden_dim * self.n_heads, e_dim, out_dim, n_heads_out,
                feat_drop, attn_drop, negative_slope,
                last_residual, last_activation, norm=last_norm, concat_out=self.concat_out
            ))
        self.head = nn.Identity() # 其作用是直接返回输入数据而不进行任何修改。

    def forward(self, g, input_feature, return_hidden=False):
        h = input_feature
        hidden_list = []
        for layer in range(self.n_layers):
            h = self.gats[layer](g, h)
            hidden_list.append(h)
        if return_hidden:
            return self.head(h), hidden_list
        else:
            return self.head(h)

    def reset_classifier(self, num_classes):
        self.head = nn.Linear(self.num_heads * self.out_dim, num_classes)


class GATConv(nn.Module):
    def __init__(self,
                 in_dim,
                 e_dim,
                 out_dim,
                 n_heads,
                 feat_drop=0.0,
                 attn_drop=0.0,
                 negative_slope=0.2,
                 residual=False,
                 activation=None,
                 allow_zero_in_degree=False,
                 bias=True,
                 norm=None,
                 concat_out=True):
        super(GATConv, self).__init__()
        self.n_heads = n_heads
        self.src_feat, self.dst_feat = expand_as_pair(in_dim)
        self.edge_feat = e_dim
        self.out_feat = out_dim
        self.allow_zero_in_degree = allow_zero_in_degree
        self.concat_out = concat_out

        if isinstance(in_dim, tuple):
            self.fc_node_embedding = nn.Linear(
                self.src_feat, self.out_feat * self.n_heads, bias=False)
            self.fc_src = nn.Linear(self.src_feat, self.out_feat * self.n_heads, bias=False)
            self.fc_dst = nn.Linear(self.dst_feat, self.out_feat * self.n_heads, bias=False)
        else:
            self.fc_node_embedding = nn.Linear(
                self.src_feat, self.out_feat * self.n_heads, bias=False)
            self.fc = nn.Linear(self.src_feat, self.out_feat * self.n_heads, bias=False)
        self.edge_fc = nn.Linear(self.edge_feat, self.out_feat * self.n_heads, bias=False)
        self.attn_h = nn.Parameter(torch.FloatTensor(size=(1, self.n_heads, self.out_feat)))
        self.attn_e = nn.Parameter(torch.FloatTensor(size=(1, self.n_heads, self.out_feat)))
        self.attn_t = nn.Parameter(torch.FloatTensor(size=(1, self.n_heads, self.out_feat)))
        self.feat_drop = nn.Dropout(feat_drop)
        self.attn_drop = nn.Dropout(attn_drop)
        self.leaky_relu = nn.LeakyReLU(negative_slope)
        if bias:
            self.bias = nn.Parameter(torch.FloatTensor(size=(1, self.n_heads, self.out_feat)))
        else:
            self.register_buffer('bias', None)
        if residual:
            if self.dst_feat != self.n_heads * self.out_feat:
                self.res_fc = nn.Linear(
                    self.dst_feat, self.n_heads * self.out_feat, bias=False)
            else:
                self.res_fc = nn.Identity()
        else:
            self.register_buffer('res_fc', None)
        self.reset_parameters()
        self.activation = activation
        self.norm = norm
        if norm is not None:
            self.norm = norm(self.n_heads * self.out_feat)

    def reset_parameters(self):
        gain = nn.init.calculate_gain('relu')
        nn.init.xavier_normal_(self.edge_fc.weight, gain=gain)
        if hasattr(self, 'fc'):
            nn.init.xavier_normal_(self.fc.weight, gain=gain)
        else:
            nn.init.xavier_normal_(self.fc_src.weight, gain=gain)
            nn.init.xavier_normal_(self.fc_dst.weight, gain=gain)
        nn.init.xavier_normal_(self.attn_h, gain=gain)
        nn.init.xavier_normal_(self.attn_e, gain=gain)
        nn.init.xavier_normal_(self.attn_t, gain=gain)
        if self.bias is not None:
            nn.init.constant_(self.bias, 0)
        if isinstance(self.res_fc, nn.Linear):
            nn.init.xavier_normal_(self.res_fc.weight, gain=gain)

    def set_allow_zero_in_degree(self, set_value):
        self.allow_zero_in_degree = set_value

    def forward(self, graph, feat, get_attention=False):
        edge_feature = graph.edata['attr']
        with graph.local_scope():
            if isinstance(feat, tuple):
                src_prefix_shape = feat[0].shape[:-1]
                dst_prefix_shape = feat[1].shape[:-1]
                h_src = self.feat_drop(feat[0])
                h_dst = self.feat_drop(feat[1])
                if not hasattr(self, 'fc_src'):
                    feat_src = self.fc(h_src).view(
                        *src_prefix_shape, self.n_heads, self.out_feat)
                    feat_dst = self.fc(h_dst).view(
                        *dst_prefix_shape, self.n_heads, self.out_feat)
                else:
                    feat_src = self.fc_src(h_src).view(
                        *src_prefix_shape, self.n_heads, self.out_feat)
                    feat_dst = self.fc_dst(h_dst).view(
                        *dst_prefix_shape, self.n_heads, self.out_feat)
            else:
                src_prefix_shape = dst_prefix_shape = feat.shape[:-1] # 图中节点数量
                h_src = h_dst = self.feat_drop(feat)
                feat_src = feat_dst = self.fc(h_src).view(
                    *src_prefix_shape, self.n_heads, self.out_feat)
                if graph.is_block:
                    feat_dst = feat_src[:graph.number_of_dst_nodes()]
                    h_dst = h_dst[:graph.number_of_dst_nodes()]
                    dst_prefix_shape = (graph.number_of_dst_nodes(),) + dst_prefix_shape[1:]
            edge_prefix_shape = edge_feature.shape[:-1]

            # 下面是用于更新图中节点、边属性（包括中间属性和最终属性）的代码，主要作用是后续利用 dgl 库中函数来更新各点参数，
            #   最终通过更新获取到的被掩码的节点的最终属性值与标签结果差距来计算损失，实现自学习。

            eh = (feat_src * self.attn_h).sum(-1).unsqueeze(-1)
            et = (feat_dst * self.attn_t).sum(-1).unsqueeze(-1)

            graph.srcdata.update({'hs': feat_src, 'eh': eh}) # 增加两个属性'hs'和'eh'
            graph.dstdata.update({'et': et}) # 增加一个属性'et' -> 注意力

            feat_edge = self.edge_fc(edge_feature).view(
                *edge_prefix_shape, self.n_heads, self.out_feat)
            ee = (feat_edge * self.attn_e).sum(-1).unsqueeze(-1)

            graph.edata.update({'ee': ee}) # 给边加一个属性，边的注意力
            graph.apply_edges(fn.u_add_e('eh', 'ee', 'ee')) # gpt说这个是在构造边表示，两个函数能够表明消息是从哪里来的
            graph.apply_edges(fn.e_add_v('ee', 'et', 'e'))
            """
            graph.apply_edges(fn.u_add_v('eh', 'et', 'e'))
            """
            e = self.leaky_relu(graph.edata.pop('e'))
            # 对每个节点的 入边 上的特征 e，在这些入边之间做 softmax，输出每条边的归一化权重（通常表示注意力值）。
            graph.edata['a'] = self.attn_drop(edge_softmax(graph, e))
            # message passing
            # 全局消息传递
            # 将源节点特征 hs 与边的注意力权重 a 相乘作为消息 m，然后将所有入边的 m 加和，作为目标节点的新特征 hs。
            graph.update_all(fn.u_mul_e('hs', 'a', 'm'),
                             fn.sum('m', 'hs'))

            rst = graph.dstdata['hs'].view(-1, self.n_heads, self.out_feat)

            if self.bias is not None:
                rst = rst + self.bias.view(
                    *((1,) * len(dst_prefix_shape)), self.n_heads, self.out_feat)

            # residual
            # 残差层，缓解梯度消失或梯度爆炸的问题，同时加速收敛。

            if self.res_fc is not None:
                # Use -1 rather than self._num_heads to handle broadcasting
                resval = self.res_fc(h_dst).view(*dst_prefix_shape, -1, self.out_feat) # 残差值
                rst = rst + resval

            if self.concat_out:
                rst = rst.flatten(1) # 从第 1 维（inclusive）开始，将后面的所有维度展平（flatten）成一个维度。
            else:
                rst = torch.mean(rst, dim=1)

            if self.norm is not None:
                rst = self.norm(rst)

                # activation
            if self.activation:
                rst = self.activation(rst)

            if get_attention:
                return rst, graph.edata['a']
            else:
                return rst

import torch.nn.functional as F

# 实现了一个基于余弦相似度的损失函数，通常称为 Scaled Cosine Error (SCE) Loss。

def sce_loss(x, y, alpha=3):
    x = F.normalize(x, p=2, dim=-1)
    y = F.normalize(y, p=2, dim=-1)
    loss = (1 - (x * y).sum(dim=-1)).pow_(alpha)
    loss = loss.mean()
    return loss

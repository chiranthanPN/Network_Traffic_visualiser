import torch
import torch.nn as nn

from torch_geometric.nn import GATConv


# =========================================================
# GRAPH ATTENTION NETWORK
# =========================================================

class GATNetwork(nn.Module):

    def __init__(
        self,
        input_dim,
        hidden_dim=64,
        heads=4,
        dropout=0.3
    ):

        super().__init__()

        # -------------------------------------------------
        # First GAT layer
        # -------------------------------------------------

        self.gat1 = GATConv(
            in_channels=input_dim,
            out_channels=hidden_dim,
            heads=heads,
            dropout=dropout
        )

        # Output dimension:
        # hidden_dim × heads
        gat_output_dim = (
            hidden_dim * heads
        )

        # -------------------------------------------------
        # Second GAT layer
        # -------------------------------------------------

        self.gat2 = GATConv(
            in_channels=gat_output_dim,
            out_channels=hidden_dim,
            heads=1,
            concat=False,
            dropout=dropout
        )

        self.dropout = nn.Dropout(
            dropout
        )

        # -------------------------------------------------
        # Edge classifier
        #
        # Source embedding + destination embedding
        # -------------------------------------------------

        self.edge_classifier = nn.Sequential(

            nn.Linear(
                hidden_dim * 2,
                hidden_dim
            ),

            nn.ReLU(),

            nn.Dropout(
                dropout
            ),

            nn.Linear(
                hidden_dim,
                2
            )
        )

    # =====================================================
    # FORWARD
    # =====================================================

    def forward(
        self,
        x,
        edge_index,
        edge_pairs
    ):

        # -------------------------------------------------
        # GAT layer 1
        # -------------------------------------------------

        x = self.gat1(
            x,
            edge_index
        )

        x = torch.relu(x)

        x = self.dropout(x)

        # -------------------------------------------------
        # GAT layer 2
        # -------------------------------------------------

        x = self.gat2(
            x,
            edge_index
        )

        x = torch.relu(x)

        # -------------------------------------------------
        # Get source node embeddings
        # -------------------------------------------------

        source_embeddings = x[
            edge_pairs[0]
        ]

        # -------------------------------------------------
        # Get destination node embeddings
        # -------------------------------------------------

        destination_embeddings = x[
            edge_pairs[1]
        ]

        # -------------------------------------------------
        # Combine source + destination
        # -------------------------------------------------

        edge_embeddings = torch.cat(
            [
                source_embeddings,
                destination_embeddings
            ],
            dim=1
        )

        # -------------------------------------------------
        # Edge classification
        # -------------------------------------------------

        logits = self.edge_classifier(
            edge_embeddings
        )

        return logits, x
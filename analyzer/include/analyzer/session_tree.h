#pragma once

#include <stdbool.h>

#include "session.h"


struct session_tree_node
{
    struct session session_;

    struct session_tree_node* left_;
    struct session_tree_node* right_;
};

struct session_tree_node* add_node(struct session_tree_node* root, struct session ses);
struct session_tree_node* find_node(struct session_tree_node* root, const char* src_dst_key);

#include "analyzer/session_tree.h"
#include "analyzer/keep_alive.h"

#include <stddef.h>

struct session_tree_node create_tree()
{
    struct session_tree_node root;
    root.left_ = NULL;
    root.right_ = NULL;
    root.session_.printed = true;
    strcpy(root.session_.src_dst, "");
    
    return root;
}

struct session_tree_node* add_node_impl(struct session_tree_node* root, struct session ses);

struct session_tree_node* add_node(struct session_tree_node* root, const char* src_dst)
{
    struct session ses;
    strcpy(ses.src_dst, src_dst);
    ses.printed = false;
    ses.got_syn_ack = false;
    ses.sent_ack = false;
    ses.expired_at_ = calculate_timestamp(keep_alive_timeout_ms);

    return add_node_impl(root, ses);
}

struct session_tree_node* add_node_impl(struct session_tree_node* root, struct session ses)
{
    struct session_tree_node *new_node = NULL;
    struct session_tree_node *pr = NULL;
    struct session_tree_node *ps = NULL; 
    bool b; 
    new_node = (struct session_tree_node *)malloc(sizeof(struct session_tree_node)); 
    
    if (!new_node)
    {
        return root;
    }
    
    new_node->session_ = ses; 
    new_node->left_ = NULL; 
    new_node->right_ = NULL; 

    if (root == NULL) 
    {
        return new_node; 
    }
    
    ps = root; 

    while (ps != NULL) 
    { 
        pr=ps;

        b = (strcmp(ses.src_dst, ps->session_.src_dst) < 0); 
        if(b)
        {
            ps = ps->left_; 
        }
        else
        {
            ps = ps->right_; 
        }
    } 

    if (b) 
    {
        pr->left_ = new_node; 
    }
    else
    {
        pr->right_ = new_node; 
    }
    return root;
}

struct session_tree_node* find_node(struct session_tree_node* root, const char* src_dst_key)
{
    if (root == NULL)
    {
        return root;
    }

    int cmp = strcmp(root->session_.src_dst, src_dst_key);
    if (cmp == 0)
    {
        return root;
    }
    if (cmp < 0)
    {
        return find_node(root->right_, src_dst_key);
    }
    else
    {
        return find_node(root->left_, src_dst_key);
    }
}

void traversal_tree(struct session_tree_node* root, traversal_cb cb)
{
    if (root == NULL)
    {
        return;
    }
    
    traversal_tree(root->left_, cb); 
    cb(root);
    traversal_tree(root->right_, cb);
}

struct session_tree_node* remove_node(struct session_tree_node* root, const char* src_dst_key, traversal_cb cb)
{
    // TODO
    return root;
}
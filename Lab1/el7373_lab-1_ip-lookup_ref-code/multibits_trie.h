#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

//#define DEBUG


/* Structure of binary trie node */
struct MBtNode{
    MBtNode  *node_0;     /* for 0000 */
    MBtNode  *node_1;     /* for 0001 */
    MBtNode  *node_2;     /* for 0010 */
    MBtNode  *node_3;     /* for 0011 */
    MBtNode  *node_4;     /* for 0100 */
    MBtNode  *node_5;     /* for 0101 */
    MBtNode  *node_6;     /* for 0110 */
    MBtNode  *node_7;     /* for 0111 */
    MBtNode  *node_8;     /* for 1000 */
    MBtNode  *node_9;     /* for 1001 */
    MBtNode  *node_a;     /* for 1010 */
    MBtNode  *node_b;     /* for 1011 */
    MBtNode  *node_c;     /* for 1100 */
    MBtNode  *node_d;     /* for 1101 */
    MBtNode  *node_e;     /* for 1110 */
    MBtNode  *node_f;     /* for 1111 */
    int     verdict;
};

/* Initialize Multi-bits trie node */
MBtNode* init_MBtnode(){
    MBtNode *ret = (MBtNode *)malloc(sizeof(MBtNode));
    ret->node_0 = NULL;
    ret->node_1 = NULL;
    ret->node_2 = NULL;
    ret->node_3 = NULL;
    ret->node_4 = NULL;
    ret->node_5 = NULL;
    ret->node_6 = NULL;
    ret->node_7 = NULL;
    ret->node_8 = NULL;
    ret->node_9 = NULL;
    ret->node_a = NULL;
    ret->node_b = NULL;
    ret->node_c = NULL;
    ret->node_d = NULL;
    ret->node_e = NULL;
    ret->node_f = NULL;
    ret->verdict = -1;
    return ret;
}

/* Clean up binary trie */
void free_bt(BtNode *root){

    if(root->left != NULL){
        free_bt(root->left);
    }
    if(root->right != NULL){
        free_bt(root->right);
    }

    free(root);
}

/* Insert a rule */
void insert_rule(BtNode *root, uint32_t prefix, int prelen, int portnum){
    static int     n_rules = 0;

#ifdef DEBUG
    uint32_t prefix_r = htonl(prefix);
    fprintf(stderr, "Insert rule: %-15s(%08x)/%d    %d\n", 
            inet_ntoa(*(struct in_addr *)&prefix_r), 
            prefix, prelen, portnum);
#endif

    n_rules ++;

    /* default rule: if packet matches none of the rules, 
     * it will match this default rule, i.e. 0.0.0.0/0 */
    if( prelen == 0 ){
        root->verdict = portnum;
        return;
    }

    uint32_t    temp_prefix = prefix;
    BtNode      *curr_node = root;
    for(int i=0 ; i<prelen ; i++){
        int     curr_bit = (temp_prefix & 0x80000000) ? 1 : 0; // take the highest bit of the prefix
        if(curr_bit == 0){
            if(curr_node->left == NULL){
                curr_node->left = init_btnode();
            }
            curr_node = curr_node->left;
        }
        else{
            if(curr_node->right == NULL){
                curr_node->right = init_btnode();
            }
            curr_node = curr_node->right;
        }
        temp_prefix = temp_prefix << 1;
    }

    if( curr_node->verdict != -1 ){
        fprintf(stderr, "Error: Rule #%d - overwriting a previous rule!! \n", n_rules);
    }
    curr_node->verdict = portnum;
}

/* Look up an IP address (represented in a uint32_t) */
int lookup_ip(BtNode *root, uint32_t ip){
    uint32_t    temp_ip = ip;
    BtNode      *curr_node = root;
    int         curr_verdict = root->verdict;
    int         curr_bit = 0;

    while(1){
        curr_bit = (temp_ip & 0x80000000) ? 1 : 0;
        if(curr_bit == 0){
            if(curr_node->left == NULL)     return curr_verdict;
            else                            curr_node = curr_node->left;
        }
        else{
            if(curr_node->right == NULL)    return curr_verdict;
            else                            curr_node = curr_node->right;
        }

        /* update verdict if current node has an non-empty verdict */
        curr_verdict = (curr_node->verdict == -1) ? curr_verdict : curr_node->verdict;
        temp_ip = temp_ip << 1;
    }
}

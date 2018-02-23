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

    if(root->node_0 != NULL){
        free_bt(root->node_0);
    }
    if(root->node_1 != NULL){
        free_bt(root->node_1);
    }
    if(root->node_2 != NULL){
        free_bt(root->node_2);
    }
    if(root->node_3 != NULL){
        free_bt(root->node_3);
    }
    if(root->node_4 != NULL){
        free_bt(root->node_4);
    }
    if(root->node_5 != NULL){
        free_bt(root->node_5);
    }
    if(root->node_6 != NULL){
        free_bt(root->node_6);
    }
    if(root->node_7 != NULL){
        free_bt(root->node_7);
    }
    if(root->node_8 != NULL){
        free_bt(root->node_8);
    }
    if(root->node_9 != NULL){
        free_bt(root->node_9);
    }
    if(root->node_a != NULL){
        free_bt(root->node_a);
    }
    if(root->node_b != NULL){
        free_bt(root->node_b);
    }
    if(root->node_c != NULL){
        free_bt(root->node_c);
    }
    if(root->node_d != NULL){
        free_bt(root->node_d);
    }
    if(root->node_e != NULL){
        free_bt(root->node_e);
    }
    if(root->node_f != NULL){
        free_bt(root->node_f);
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

    // TODO: prefix extension
    int mode = (prelen % 4);
    if (mode != 0) {
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
int lookup_ip(MBtNode *root, uint32_t ip){
    uint32_t    temp_ip = ip;
    MBtNode     *curr_node = root;
    int         curr_verdict = root->verdict;
    int         curr_bits = 0;

    while(1){
        curr_bits = (temp_ip & 0xf0000000) >> 28;
        if(curr_bits == 0){
            if(curr_node->node_0 == NULL)     return curr_verdict;
            else                            curr_node = curr_node->node_0;
        }
        else if(curr_bits == 1){
            if(curr_node->node_1 == NULL)     return curr_verdict;
            else                            curr_node = curr_node->node_1;
        }
        else if(curr_bits == 2){
            if(curr_node->node_2 == NULL)     return curr_verdict;
            else                            curr_node = curr_node->node_2;
        }
        else if(curr_bits == 3){
            if(curr_node->node_3 == NULL)     return curr_verdict;
            else                            curr_node = curr_node->node_3;
        }
        else if(curr_bits == 4){
            if(curr_node->node_4 == NULL)     return curr_verdict;
            else                            curr_node = curr_node->node_4;
        }
        else if(curr_bits == 5){
            if(curr_node->node_5 == NULL)     return curr_verdict;
            else                            curr_node = curr_node->node_5;
        }
        else if(curr_bits == 6){
            if(curr_node->node_6 == NULL)     return curr_verdict;
            else                            curr_node = curr_node->node_6;
        }
        else if(curr_bits == 7){
            if(curr_node->node_7 == NULL)     return curr_verdict;
            else                            curr_node = curr_node->node_7;
        }
        else if(curr_bits == 8){
            if(curr_node->node_8 == NULL)     return curr_verdict;
            else                            curr_node = curr_node->node_8;
        }
        else if(curr_bits == 9){
            if(curr_node->node_9 == NULL)     return curr_verdict;
            else                            curr_node = curr_node->node_9;
        }
        else if(curr_bits == 10){
            if(curr_node->node_a == NULL)     return curr_verdict;
            else                            curr_node = curr_node->node_a;
        }
        else if(curr_bits == 11){
            if(curr_node->node_b == NULL)     return curr_verdict;
            else                            curr_node = curr_node->node_b;
        }
        else if(curr_bits == 12){
            if(curr_node->node_c == NULL)     return curr_verdict;
            else                            curr_node = curr_node->node_c;
        }
        else if(curr_bits == 13){
            if(curr_node->node_d == NULL)     return curr_verdict;
            else                            curr_node = curr_node->node_d;
        }
        else if(curr_bits == 14){
            if(curr_node->node_e == NULL)     return curr_verdict;
            else                            curr_node = curr_node->node_e;
        }
        else if(curr_bits == 15){
            if(curr_node->node_f == NULL)     return curr_verdict;
            else                            curr_node = curr_node->node_f;
        }

        /* update verdict if current node has an non-empty verdict */
        curr_verdict = (curr_node->verdict == -1) ? curr_verdict : curr_node->verdict;
        temp_ip = temp_ip << 4;
    }
}

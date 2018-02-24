#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <math.h>

//#define DEBUG

/* Structure of binary trie node */
struct PCtNode{
    PCtNode  *left;      /* for 0 */
    PCtNode  *right;     /* for 1 */
    int     verdict;
    int     skip;
    int     segment;
};

/* Initialize binary trie node */
PCtNode* init_pctnode(){
    PCtNode *ret = (PCtNode *)malloc(sizeof(PCtNode));
    ret->left = NULL;
    ret->right = NULL;
    ret->verdict = -1;
    ret->skip = 0;
    ret->segment = -1;
    return ret;
}

/* Clean up binary trie */
void free_pct(PCtNode *root){

    if(root->left != NULL){
        free_pct(root->left);
    }
    if(root->right != NULL){
        free_pct(root->right);
    }

    free(root);
}

/* Insert a rule */
void insert_rule(PCtNode *root, uint32_t prefix, int prelen, int portnum){
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
    PCtNode      *curr_node = root;
    for(int i=0 ; i<prelen ; i++){
        int     curr_bit = (temp_prefix & 0x80000000) ? 1 : 0; // take the highest bit of the prefix
        if(curr_bit == 0){
            if(curr_node->left == NULL){
                curr_node->left = init_pctnode();
            }
            curr_node = curr_node->left;
        }
        else{
            if(curr_node->right == NULL){
                curr_node->right = init_pctnode();
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

/* Generate bit mask according to the prefix length*/
int get_mask(int prelen) {
    int mask = 0;
    long offset = pow(2L, prelen + 1) - 1;
    //fprintf(stderr, "input prefix:%d - output mask:%x - offset:%x \n", prelen, ((mask + offset) << (31 - prelen)), offset);
    return ((mask + offset) << (31 - prelen));
}

/* Look up an IP address (represented in a uint32_t) */
int lookup_ip(PCtNode *root, uint32_t ip){
    uint32_t    temp_ip = ip;
    PCtNode      *curr_node = root;
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

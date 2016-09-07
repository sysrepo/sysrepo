%module tree

%{
/* Includes the header in the wrapper code */
#include "Tree.h"
%}

%ignore Tree::Tree(sr_node_t *tree, bool free = false);
%ignore Tree::get();
%ignore Tree::tree();

%ignore Trees::Trees(sr_node_t **trees, size_t *cnt, size_t n);
%ignore Trees::Trees(const sr_node_t *trees, const size_t n);
%ignore Trees::p_trees_cnt();
%ignore Trees::p_trees();
%ignore Trees::trees();

%include "Tree.h"

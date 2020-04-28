"
" An example for a vimrc file.
"
"
" Korean localization by CHOI Junho <cjh@kr.FreeBSD.org>
"

" Normally we use vim-extensions. If you want true vi-compatibility
" remove change the following statements
set nocompatible	" Use Vim defaults (much better!)
set backspace=2		" allow backspacing over everything in insert mode
" Now we set some defaults for the editor 
set autoindent		" always set autoindenting on
set textwidth=0		" Don't wrap words by default
set nobackup		" Don't keep a backup file
set viminfo='20,\"50	" read/write a .viminfo file, don't store more than
			" 50 lines of registers
set history=50		" keep 50 lines of command line history
set ruler		" show the cursor position all the time
set laststatus=2
set statusline=%<%f%=\ [%1*%M%*%n%R%H]\ \ %-25(%3l,%c%03V\ \ %P\ (%L)%)%12o'%03b'
set expandtab
set tabstop=8
set shiftwidth=4
set softtabstop=4
set fileencodings=euc-kr,utf-8
set encoding=euc-kr
set termencoding=euc-kr
set background=dark
set title

set magic
set showmode
set showmatch
set esckeys
set incsearch
set ttyfast

set nocompatible
set novisualbell
set noerrorbells
set nohidden
set nohlsearch
set nonumber
set notitle
set noicon

set cindent

" Suffixes that get lower priority when doing tab completion for filenames.
" These are files we are not likely to want to edit or read.
set suffixes=.bak,~,.swp,.o,.info,.aux,.log,.dvi,.bbl,.blg,.brf,.cb,.ind,.idx,.ilg,.inx,.out,.toc

" We know xterm-debian is a color terminal
if &term =~ "xterm" || &term =~ "xterm-xfree86" || &term =~ "xterm-color" || &term =~ "vt220" || &term=~ "Eterm" || &term =~ "eterm"
  set t_Co=8
"  set t_Sf=[3%dm
"  set t_Sb=[4%dm
  set t_AF=[%?%p1%{8}%<%t3%p1%d%e%p1%{22}%+%d;1%;m
  set t_AB=[%?%p1%{8}%<%t4%p1%d%e%p1%{32}%+%d;1%;m
endif

" Make p in Visual mode replace the selected text with the "" register.
vnoremap p <Esc>:let current_reg = @"<CR>gvdi<C-R>=current_reg<CR><Esc>

" Vim5 and later versions support syntax highlighting. Uncommenting the next
" 3 lines enables syntax highlighting by default.
if has("syntax") && &t_Co > 2
  syntax on
endif

" Debian uses compressed helpfiles. We must inform vim that the main
" helpfiles is compressed. Other helpfiles are stated in the tags-file.
set helpfile=$VIMRUNTIME/doc/help.txt

if has("autocmd")
 " Enabled file type detection
 " Use the default filetype settings. If you also want to load indent files
 " to automatically do language-dependent indenting add 'indent' as well.
 filetype plugin on
 au BufNewFile,BufRead *.jsp,*.html,*.htm,*.css,*.js set sw=2 sts=2 et mps+=<:>

endif " has ("autocmd")

" The following are commented out as they cause vim to behave a lot
" different from regular vi. They are highly recommended though.
"set showcmd		" Show (partial) command in status line.
set showmatch		" Show matching brackets.
"set ignorecase		" Do case insensitive matching
set incsearch		" Incremental search
"set autowrite		" Automatically save before commands like :next and :make
set t_k5=[16~
set t_k6=[17~
set t_k7=[18~
set t_k8=[19~
set t_k9=[20~
set t_k1=[11~
set t_k2=[12~
set t_k3=[13~
set t_k4=[14~

"set tags=/user/jcom/alpha/src/pims/tags
set tags=/user/jcom/beta/web/WEB-INF/classes/beans/tags
"nmap v :s/.*/\/*&*\//
"nmap V :s/[\/*][*\/]//g

nmap R gR
nmap <F2> :s/.*/\/*&*\//<CR>
nmap <F3> :s/\/\*\(.*\)\*\//\1/<CR>
nmap <F5> :20vs ./<CR>
nmap <F9> :set invpaste<CR>
nmap ,t :echo strftime("%Y %T")<CR>

com -nargs=0 Html :so $VIMRUNTIME/syntax/2html.vim

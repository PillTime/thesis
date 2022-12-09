#!/usr/bin/perl
# This script cleans the auxiliary files created during a LaTeX compile
unlink <*.aux *.log *.dvi *.out *.failed *.bbl *.blg *~ *.ps *.idx *.ind *.ilg *.brf *.toc *.lof *.ist *.lot *.dep *.lol *.fls *.bcf>;


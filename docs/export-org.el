(defun directory-org-files (directory)
  "Like `directory-files', but excluding \".\" and \"..\"."
  (delete "." (delete ".." (directory-files directory nil ".org$" ))))


(mapc
  (lambda (f) (interactive "")
      (with-current-buffer
        (switch-to-buffer (find-file-noselect f))
        (org-md-export-to-markdown)
        (kill-buffer)))
  (directory-org-files default-directory))



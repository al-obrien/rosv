% Generated by roxygen2: do not edit by hand
% Please edit documentation in R/scans.R
\name{osv_scan}
\alias{osv_scan}
\title{Use OSV database to scan for vulnerabilities}
\usage{
osv_scan(mode, ...)
}
\arguments{
\item{mode}{The kind of scan to perform.}

\item{...}{Parameters passed to specific underlying functions for mode selected.}
}
\value{
A data.frame specifying which packages are vulnerable or not.
}
\description{
Scan project based upon specified mode to determine if any vulnerable packages are detected.
}
\details{
The available scanning modes are: 'r_project', 'renv', and 'r_libath'. The 'r_libpath' mode
simply performs all R project related scans at once. Emphasis is placed on scans of R related content.
Additional parsing and scanning modes will be added over time as needed. If a mode does not exist for
a particular purpose, alternate functions such as \code{is_pkg_vulnerable()} can be used with any list of
package names for ecosystems available in the OSV database.
}
\examples{
\dontshow{if (interactive()) (if (getRversion() >= "3.4") withAutoprint else force)(\{ # examplesIf}
osv_scan('r_libpath')
\dontshow{\}) # examplesIf}
}
\seealso{
\code{\link{is_pkg_vulnerable}}
}

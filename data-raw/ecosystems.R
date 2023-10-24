# Save a copy of available ecosystems locally

osv_ecosystems <- fetch_ecosystems()
usethis::use_data(osv_ecosystems, overwrite = TRUE, internal = TRUE)

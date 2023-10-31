without_internet({
  test_that("Can create a well-formed RosvQueryBatch object...", {
    # For 1 input
    querybatch <- RosvQueryBatch$new(name = c('dask'), ecosystem = c('PyPI'))
    expect_POST(querybatch$run(),
                'https://api.osv.dev/v1/querybatch',
                '{"queries":[{"commit":null,"version":null,"package":{"name":"dask","ecosystem":"PyPI","purl":null},"page_token":null}]}')

    # For >1 input
    querybatch <- RosvQueryBatch$new(name = c('dask', 'readxl'), ecosystem = c('PyPI', 'CRAN'))
    expect_POST(querybatch$run(),
                'https://api.osv.dev/v1/querybatch',
                '{"queries":[{"commit":null,"version":null,"package":{"name":"dask","ecosystem":"PyPI","purl":null},"page_token":null},{"commit":null,"version":null,"package":{"name":"readxl","ecosystem":"CRAN","purl":null},"page_token":null}]}')
  })
})

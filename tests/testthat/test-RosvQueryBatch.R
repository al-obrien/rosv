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

without_internet({
  test_that("Check error checking on RosvQueryBatch objects...", {

    # Must give valid ecosystem
    expect_error(RosvQueryBatch$new(name = c('pandas'), ecosystem = c('PyI')))

    # Combination errors checked
    expect_error(RosvQueryBatch$new(name = c('pandas')),
                 'If using package name, ecosystem must also be set')
    expect_error(RosvQueryBatch$new(commit = 'somerandomhash', version = '1.0.0'),
                 'Cannot provide commit hash and version at the same time')
    expect_error(RosvQueryBatch$new(commit = 'somerandomhash', name = 'pandas', ecosystem = 'PyPI'),
                 'Separate commit hash queries from package based queries')
    expect_error(RosvQueryBatch$new(purl = 'somepackageurl', name = 'pandas'),
                 'Cannot provide purl with name or ecosystem also set.')
    expect_error(RosvQueryBatch$new(name = c('pandas'), version = c('1.1', '1.2'), ecosystem = 'PyPI'),
                 'Package name and versions must be same length for vectorized operation')
  })
})

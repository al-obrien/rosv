without_internet({
  test_that("Can create a well-formed RosvQuery1 object...", {
    query_1 <- RosvQuery1$new(name = 'dask', ecosystem = 'PyPI')
    expect_POST(query_1$run(),
                'https://api.osv.dev/v1/query',
                '{"commit":null,"version":null,"package":{"name":"dask","ecosystem":"PyPI","purl":null},"page_token":null}')
  })
})

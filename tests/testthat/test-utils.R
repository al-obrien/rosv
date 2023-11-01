test_that('PyPI package names can be normalized...', {
  expect_equal(normalize_pypi_pkg(c('Dask', 'TenSorFlow')), c('dask', 'tensorflow'))
})

test_that('Correct ecosystems can be checked...', {
  skip_on_cran()
  expect_equal(check_ecosystem(c('PyPI', 'CRAN')), c('PyPI', 'CRAN'))
  expect_error(check_ecosystem(c('pypi')))
})

test_that('Ensure rosv type check is selective...', {
  expect_true(is_rosv(RosvQuery1$new(name = 'pandas', ecosystem = 'PyPI')))
  expect_true(is_rosv(RosvQueryBatch$new(name = 'pandas', ecosystem = 'PyPI')))
  expect_true(is_rosv(RosvVulns$new('RSEC-2023-6')))

  expect_true(validate_rosv(RosvQuery1$new(name = 'pandas', ecosystem = 'PyPI')))
  expect_true(validate_rosv(RosvQueryBatch$new(name = 'pandas', ecosystem = 'PyPI')))
  expect_true(validate_rosv(RosvVulns$new('RSEC-2023-6')))

  expect_false(is_rosv(c(1,2,3)))
  expect_false(is_rosv(data.frame(test = c(1,2,3))))

  expect_error(validate_rosv(c(1,2,3)))
  expect_error(validate_rosv(data.frame(test = c(1,2,3))))
})

// A separate module that consumes the public detector package the way a host such as Culvert would: by
// import path, from outside the detector module, with none of the repository's fixtures (working plan #19).
// The replace directive points at the local checkout for this test only; a host pins a released version.
module example.test/detectorconsumer

go 1.27.0

require github.com/leenadav/protocol-detector/go v0.0.0

replace github.com/leenadav/protocol-detector/go => ../
